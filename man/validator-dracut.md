% validator-dracut(1) validator | User Commands

# NAME

validator dracut module

# DESCRIPTION

Validator ships with a dracut module which allows you to easily
install files during boot (in the initramfs).

When the validator module is enabled, the validator-boot.service
systemd service will be installed into the initrd and run after
*initrd.target* and before *initrd-switch-root.target*. This service
looks for and executes validator install config files with a *.conf*
prefix in /etc/validator/boot.d and /usr/lib/validator/boot.d.

Enabling the module also copies any config files in these directories
on the system into the initramfs. Additionally, any files in
/etc/validator/keys and /usr/lib/validator/keys will also be copied
into the initrd, making it easy to refer to keys here in the config
files.

Note that the dracut module runs in the initramfs, which means that
the to-be-booted system is mounted at `/sysroot`, and all filesystems
may not be mounted yet. However, running in the initramfs is
advantageous for security reasons, because if secureboot (or similar)
is used, then at that point all the files in the system (like the key
files) other than the sysroot are trusted.

For more information about the config file format, see
**validator-config(5)**.

# EXAMPLE

As an example, a file called `/usr/lib/validator/boot.d/etc.conf`,
containing:

```
[install]
keys=/usr/lib/validator/keys/etc.key
sources=/sysroot/opt/extra-etc
destination=/sysroot/etc
```

And a public key stored in `/usr/lib/validator/keys/etc.key` will, if
the validator dracut module is enabled, cause any valid, signed files
in `/opt/extra-etc` to be copied into `/etc` during early boot. This
setup is very useful if `/etc` is transient, such as when using
**systemd-volatile-root.service(8)**, and you want to be able to
extend the configuration of individual systems.

# SEE ALSO
**validator(1)**, **validator-install(1)**, **validator-config(5)**

[validator upstream](https://github.com/containers/validator)
