AC_PREREQ([2.69])
AC_INIT([validator], [0.2.2], [alexl@redhat.com])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

AM_INIT_AUTOMAKE([1.11.2 -Wno-portability foreign tar-ustar no-dist-gzip dist-xz subdir-objects])

AC_PROG_CC
PKG_PROG_PKG_CONFIG
m4_ifdef([PKG_INSTALLDIR], [PKG_INSTALLDIR], AC_SUBST([pkgconfigdir], ${libdir}/pkgconfig))

PKGCONFIG_REQUIRES=
PKGCONFIG_REQUIRES_PRIVATELY=

PKG_CHECK_MODULES(DEPS, libcrypto glib-2.0)

AC_DEFUN([CC_CHECK_FLAG_APPEND], [
  AC_CACHE_CHECK([if $CC supports flag $3 in envvar $2],
                 AS_TR_SH([cc_cv_$2_$3]),
          [eval "AS_TR_SH([cc_save_$2])='${$2}'"
           eval "AS_TR_SH([$2])='${cc_save_$2} -Werror `echo "$3" | sed 's/^-Wno-/-W/'`'"
           AC_LINK_IFELSE([AC_LANG_SOURCE(ifelse([$4], [],
                                                 [int main(void) { return 0; } ],
                                                 [$4]))],
                          [eval "AS_TR_SH([cc_cv_$2_$3])='yes'"],
                          [eval "AS_TR_SH([cc_cv_$2_$3])='no'"])
           eval "AS_TR_SH([$2])='$cc_save_$2'"])

  AS_IF([eval test x$]AS_TR_SH([cc_cv_$2_$3])[ = xyes],
        [eval "$1='${$1} $3'"])
])

AC_DEFUN([CC_CHECK_FLAGS_APPEND], [
  for flag in [$3]; do
    CC_CHECK_FLAG_APPEND([$1], [$2], $flag, [$4])
  done
])

AC_ARG_WITH(dracut,
            AS_HELP_STRING([--with-dracut],
                           [Install dracut module (default: yes)]),,
              [with_dracut=yes])
AM_CONDITIONAL(BUILDOPT_DRACUT, test x$with_dracut = xyes)

AS_IF([echo "$CFLAGS" | grep -q -E -e '-Werror($| )'], [], [
CC_CHECK_FLAGS_APPEND([WARN_CFLAGS], [CFLAGS], [\
  -pipe \
  -Wall \
  -Werror=shadow \
  -Werror=empty-body \
  -Werror=strict-prototypes \
  -Werror=missing-prototypes \
  -Werror=implicit-function-declaration \
  "-Werror=format=2 -Werror=format-security -Werror=format-nonliteral" \
  -Werror=pointer-arith -Werror=init-self \
  -Werror=missing-declarations \
  -Werror=return-type \
  -Werror=switch \
  -Werror=overflow \
  -Werror=int-conversion \
  -Werror=parentheses \
  -Werror=undef \
  -Werror=incompatible-pointer-types \
  -Werror=misleading-indentation \
  -Werror=missing-include-dirs  \
  -Wstrict-aliasing=2 \
  -Werror=unused-result \
])])
AC_SUBST(WARN_CFLAGS)


AC_CONFIG_FILES([
Makefile
validator.spec
])
AC_OUTPUT

echo "
    validator $VERSION
    ===============


    dracut:                                       $with_dracut
"
