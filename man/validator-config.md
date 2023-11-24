% validator-config(5) validator | User Commands

# NAME

validator-config - Format for validator install config giles

# DESCRIPTION

Validator install lets you specify a config file, or a directory of
config files instead of using command line options. This makes it
easy to drop in configurations of what files to install where
with just a single files.

The format is a .ini style key-value file, with a single group
called *[install]*, and a typical example may look like this:

```
[install]
keys=/usr/lib/validator/keys/etc.key
sources=/opt/extra-ext
destination=/etc
```

Supported keys are:

**keys**=*PATH*
:   A semicolon separated list of public key files

**key_dirs**=*PATH*
:   A semicolon separated list of directories containing public key files

**destination**=*PATH*
:   The destination of the files to install

**source**=*PATH*
:   A semicolon separated list of files to install

**recursive**=[true|false]
:   Whether to do a recursive copy or not (default *true*)

**force**=[true|false]
:   Whether to replace existing destingaiont or not (default *true*)

**path_relative**=*PATH*
:   Optional path to use as the base for the source filename signatures

**path_prefix**=*PATHPREFIX*
:   Optional path prefix to use for the source filename signatures


# SEE ALSO
**validator(1)**, **validator-sign(1)**, **validator-install(1)**

[validator upstream](https://github.com/containers/validator)
