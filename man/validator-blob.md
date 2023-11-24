% validator-blob(1) validator | User Commands

# NAME

validator blob - generate data for external signatures

# SYNOPSIS
**validator** blob [OPTIONS..] FILE

# DESCRIPTION

Validator blob generates the data used for signing a particular file,
including checksums of its content and the filename used. This can be
used to sign the file using any external signing tool that supports
Ed25519.

This can be useful to when the private key is not just a regular file,
but a more secure setup is used.

The data is output to stdout.

After signing the blob, an 8 byte header of "VALIDTR\001" needs to be
added to it before using it as a validator signature file.

# OPTIONS

**validator validate** accepts the following global options:

**\-\-relative-to**
:   Sign files with filenames relative to this path

**\-\-path-prefix**
:   In addition to the filename that would otherwise have been used,
    append this prefix to the filename used for signing.

# EXAMPLE

Here is an example of using openssl to sign a file "myfile", such that it
can be installed as "mydir/myfile" in a destination directory.

```
$ validator blob --path-prefix=mydir /path/to/myfile > blob
$ openssl pkeyutl -sign -inkey /path/to/seckey -rawin -in blob -out blob.rawsig
$ echo -n  $'VALIDTR\001' > sig_header
$ cat sig_header $TMPDIR/blob.rawsig > /path/to/myfile.sig
```

# SEE ALSO
**validator(1)**, **validator-sign(1)**

[validator upstream](https://github.com/containers/validator)
