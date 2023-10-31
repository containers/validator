#!/bin/bash

BUILDDIR=$1
SRCDIR=$2
VALIDATOR=$BUILDDIR/validator
ASSETS=$SRCDIR/test-assets

set -e

HEADER() {
      echo === $@ ===
}

fatal() {
    echo $@ 1>&2; exit 1
}

assert_has_file () {
    test -f "$1" || fatal "Couldn't find '$1'"
}

assert_not_has_file () {
    if test -f "$1"; then
        _fatal_print_file "$1" "File '$1' exists"
    fi
}

assert_has_dir () {
    test -d "$1" || fatal "Couldn't find '$1'"
}

# Dump ls -al + file contents to stderr, then fatal()
_fatal_print_file() {
    file="$1"
    shift
    ls -al "$file" >&2
    sed -e 's/^/# /' < "$file" >&2
    fatal "$@"
}

assert_file_has_content () {
    fpath=$1
    shift
    for re in "$@"; do
        if ! grep -q -e "$re" "$fpath"; then
            _fatal_print_file "$fpath" "File '$fpath' doesn't match regexp '$re'"
        fi
    done
}

TMPDIR=$(mktemp -d /tmp/validator-test.XXXXXX)
trap 'rm -rf -- "$TMPDIR"' EXIT

OUT=$TMPDIR/out
COPY=$TMPDIR/copy
CONTENT=$TMPDIR/content
SECKEY=$TMPDIR/secret.pem
PUBDIR=$TMPDIR/keys/
PUBKEY=$PUBDIR/public.der

$VALIDATOR --version > $TMPDIR/version

genkeys () {
    mkdir -p $TMPDIR/keys
    openssl genpkey -algorithm ed25519 -outform PEM -out $TMPDIR/secret.pem
    openssl pkey -in $TMPDIR/secret.pem  -pubout -out $TMPDIR/keys/public.der
}

gencontent () {
    DIR=$1
    rm -rf $DIR
    mkdir -p $DIR/dir
    echo FILEDATA1 > $DIR/file1.txt
    echo FILEDATA2 > $DIR/file2.txt
    ln -s file1.txt  $DIR/symlink1
    echo FILEDATA3 > $DIR/dir/file3.txt
    ln -s file3.txt  $DIR/dir/symlink2
}

genkeys
gencontent $CONTENT

HEADER Sign all
$VALIDATOR sign -r --key=$SECKEY $CONTENT

HEADER Ensure all are signed
assert_has_file $CONTENT/file1.txt.sig
assert_has_file $CONTENT/file2.txt.sig
assert_has_file $CONTENT/symlink1.sig
assert_has_file $CONTENT/dir/file3.txt.sig
assert_has_file $CONTENT/dir/symlink2.sig

HEADER Validate all
$VALIDATOR validate -r --key=$PUBKEY $CONTENT

HEADER Validate individually
$VALIDATOR validate --key=$PUBKEY $CONTENT/file1.txt
$VALIDATOR validate --key=$PUBKEY $CONTENT/file2.txt
$VALIDATOR validate --key=$PUBKEY $CONTENT/symlink1
$VALIDATOR validate --key=$PUBKEY --relative-to=$CONTENT $CONTENT/dir/file3.txt
$VALIDATOR validate --key=$PUBKEY --relative-to=$CONTENT $CONTENT/dir/symlink2

HEADER Test missing signatures
rm  $CONTENT/file1.txt.sig
rm  $CONTENT/dir/file3.txt.sig
if $VALIDATOR validate -r --key=$PUBKEY $CONTENT 2> $OUT; then
   fatal "Should not have validated"
fi
assert_file_has_content $OUT "No signature for .*file1.txt"
assert_file_has_content $OUT "No signature for .*file3.txt"

if $VALIDATOR validate --key=$PUBKEY $CONTENT/file1.txt 2> $OUT; then
   fatal "Should not have validated"
fi
assert_file_has_content $OUT "No signature for .*file1.txt"

if $VALIDATOR validate --key=$PUBKEY --relative-to=$CONTENT $CONTENT/dir/file3.txt 2> $OUT; then
   fatal "Should not have validated"
fi
assert_file_has_content $OUT "No signature for .*file3.txt"

HEADER Sign individual
$VALIDATOR sign --key=$SECKEY $CONTENT/file1.txt
$VALIDATOR sign --key=$SECKEY --relative-to $CONTENT $CONTENT/dir/file3.txt

$VALIDATOR validate --key=$PUBKEY $CONTENT/file1.txt
$VALIDATOR validate --key=$PUBKEY --relative-to=$CONTENT $CONTENT/dir/file3.txt

$VALIDATOR validate -r --key=$PUBKEY $CONTENT/

HEADER Test failed signatures

echo wrongdata >> $CONTENT/dir/file3.txt
ln -sf wronglink $CONTENT/symlink1

if $VALIDATOR validate -r --key=$PUBKEY $CONTENT 2> $OUT; then
   fatal "Should not have validated"
fi
assert_file_has_content $OUT "Signature of .*symlink1.* is invalid"
assert_file_has_content $OUT "Signature of .*file3.txt.* is invalid"

HEADER Re-Sign all forced
$VALIDATOR sign -f -r --key=$SECKEY $CONTENT
$VALIDATOR validate -r --key=$PUBKEY $CONTENT

HEADER Externally signed blob gives same result
for i in file1.txt file2.txt symlink1 dir/file3.txt dir/symlink2  ; do
    $VALIDATOR blob --relative-to=$CONTENT $CONTENT/$i > $TMPDIR/blob
    openssl pkeyutl -sign -inkey $SECKEY -rawin -in $TMPDIR/blob -out $TMPDIR/blob.sig
    cmp $CONTENT/$i.sig $TMPDIR/blob.sig
done

# Reset content
gencontent $CONTENT

HEADER Install unsigned should fail
mkdir -p $COPY

if $VALIDATOR install -r --key=$PUBKEY $CONTENT $COPY 2> $OUT; then
    fatal "Should fail"
fi
assert_file_has_content $OUT "No signature for .*file1.txt"
assert_file_has_content $OUT "No signature for .*file3.txt"

assert_not_has_file $COPY/file1.txt
assert_not_has_file $COPY/file2.txt
assert_not_has_file $COPY/symlink1
assert_not_has_file $COPY/dir

HEADER Install signed should succeed
mkdir -p $COPY

$VALIDATOR sign -f -r --key=$SECKEY $CONTENT
$VALIDATOR install -r --key=$PUBKEY $CONTENT $COPY

assert_has_file $COPY/file1.txt
assert_has_file $COPY/file2.txt
assert_has_file $COPY/symlink1
assert_has_file $COPY/dir/file3.txt
assert_has_file $COPY/dir/symlink2

HEADER Partial install
rm -rf $COPY
mkdir -p $COPY

rm $CONTENT/dir/symlink2.sig
echo wrong > $CONTENT/file2.txt

if $VALIDATOR install -r --key=$PUBKEY $CONTENT $COPY 2> $OUT; then
    fatal "Should fail"
fi

assert_file_has_content $OUT "No signature for .*symlink2"
assert_file_has_content $OUT "Signature of .*file2.txt.* is invalid"

assert_has_file $COPY/file1.txt
assert_not_has_file $COPY/file2.txt
assert_has_file $COPY/symlink1
assert_has_file $COPY/dir/file3.txt
assert_not_has_file $COPY/dir/symlink2

HEADER Compatible with existing keys/signatures
# NOTE: Update this with:./validator sign -rf --key=test-assets/secret.pem --relative-to=test-assets/content test-assets/content

$VALIDATOR validate -r --key=$ASSETS/public.der $ASSETS/content

echo ALL TESTS OK!
