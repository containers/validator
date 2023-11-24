% validator-validate(1) validator | User Commands

# NAME

validator validate - validate signed files

# SYNOPSIS
**validator** validate [OPTIONS..] FILES...

# DESCRIPTION

Validator sign lets you validate files signed with validator,

# OPTIONS

**validator validate** accepts the following global options:

**\-\-key**=*PATH*
:   Validate with the key. May be specified several times.

**\-\-key-dir**=*PATH*
:   Validate with any of the keys in the given directory. May be
    specified several times.

**\-\-recursive**, **-r**
:   If a specified file is a directory, validate all files in it
    recursively

**\-\-relative-to**
:   Sign files with filenames relative to this path


# SEE ALSO
**validator(1)**, **validator-sign(1)**, **validator-install(1)** , **validator-validate(1)**, **validator-blob(1)**

[validator upstream](https://github.com/containers/validator)
