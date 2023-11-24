% validator-sign(1) validator | User Commands

# NAME

validator sign - sign files

# SYNOPSIS
**validator** sign [OPTIONS..] FILES...

# DESCRIPTION

Validator sign lets you sign one or more files and its relative
filename given a private (Ed25519) key. The signature of a file is a
file with the same filename and the extension ".sig" next to the file.

Both regular files and symlinks can be signed. If a directory is
specified the contents of it can (optionally) be signed recursively.

Each file is signed as a particular filename, which is a path relative
to a location of your choice. This allow you to validate not only the
content of a file but also the expected name and location of it.

By default the basename is used as the filename, or if a directory is
specified, files in the directory are signed relative to that
directory.

# OPTIONS

**validator sign** accepts the following global options:

**\-\-key**=*PATH*
:   Sign with the Ed25519 private key (in PEM format) given by the
    path.

**\-\-recursive**, **-r**
:   If a specified file is a directory, sign all files in it
    recursively

**\-\-force**, **-f**
:   If a file is already signed, still sign it and replace the
    existing signature.

**\-\-relative-to**
:   Sign files with filenames relative to this path

**\-\-path-prefix**
:   In addition to the filename that would otherwise have been used,
    append this prefix to the filename used for signing.

# EXAMPLE

Here is an example of how you would sign a *foo.conf* file to allow it
to be installed it as */etc/foo.conf* later.

```
$ openssl genpkey -algorithm ed25519 -outform PEM -out secret.pem
$ validator --verbose --key=secret.pem  sign foo.conf
Loaded private key 'secret.pem'
Wrote signature foo.conf.sig' (for path foo.conf)
```

Here is how you would then install this into /etc, giving */etc/foo.conf*:
```
$ openssl pkey -in secret.pem -pubout -out public.pem
$ validator --verbose install --key=public.pem foo.conf /etc
Loaded public key 'public.pem'
Installed file /'etc/foo.conf'
```

# SEE ALSO
**validator(1)**, **validator-install(1)** , **validator-validate(1)**, **validator-blob(1)**

[validator upstream](https://github.com/containers/validator)
