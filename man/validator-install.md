% validator-install(1) validator | User Commands

# NAME

validator install - install valid signed files

# SYNOPSIS
**validator** install [OPTIONS..] DESTDIR FILES...

# DESCRIPTION

Validator install lets you install files signed with validator. Only files
with a valid signature (for the source filename) are copied.

# OPTIONS

**validator intall** accepts the following global options:

**\-\-key**=*PATH*
:   Validate with the key. May be specified several times.

**\-\-key-dir**=*PATH*
:   Validate with any of the keys in the given directory. May be
    specified several times.

**\-\-recursive**, **-r**
:   If a specified file is a directory, install all files in it
    recursively

**\-\-force**, **-f**
:   If a destination file already exists, replace it.

**\-\-relative-to**
:   Validate files with filenames relative to this path

**\-\-path-prefix**
:   In addition to the filename that would otherwise have been used,
    append this prefix to the filename used for validating.

**\-\-config**=*PATH*
:   Use a separate configuration file to specify a separate set of
    install options. See validator-config(5) for details of the config
    format. May be specified several times.

**\-\-config-dir**=*PATH*
:   Use a directory of separate configuration files, each will specify
    a separate set of install options. See validator-config(5) for
    details of the config format. May be specified several times.

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
**validator(1)**, **validator-sign(1)**, **validator-install(1)** , **validator-config(1)**

[validator upstream](https://github.com/containers/validator)
