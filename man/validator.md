% validator(1) validator | User Commands

# NAME

validator - sign, validate and install files

# SYNOPSIS
**validator** [sign|install|validate|blob] [OPTIONS..]

# DESCRIPTION

Validator is a tool that lets you sign and validate files and
filenames, with the goal of installing them somewhere (if valid). A
common example is a system with a read-only root filesystem, with a
tmpfs-backed /etc where you want to be able to dynamically add files
from a limited, controlled set.

# OPTIONS

**validator** accepts the following global options:

**\-\-verbose**
:   Show debug information when running.

**\-\-version**
:   Print version information and exit.

**\-\-help**
:   Print usage help and exit.


# COMMANDS

The first argument to **validator** is the command, these are the supported commands.

**validator-sign(1)**
:   Sign file or files with a given secret key

**validator-install(1)**
:   Install signed files to destination (if valid)

**validator-validate(1)**
:   Validete files in place

**validator-blob(1)**
:   Generate data used for signing files externally

# SEE ALSO
**validator-sign(1)**, **validator-install(1)** , **validator-validate(1)**, **validator-blob(1)**

[validator upstream](https://github.com/containers/validator)
