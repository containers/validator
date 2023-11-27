bin_PROGRAMS = validator

include Makefile.clang

AM_CFLAGS = $(DEPS_CFLAGS) $(WARN_CFLAGS) -I$(top_srcdir)/

validator_SOURCES = main.c main.h utils.c utils.h sign.c validate.c install.c blob.c
validator_LDADD =  $(DEPS_LIBS)

MAN1PAGES=\
	man/validator.md \
	man/validator-sign.md \
	man/validator-install.md \
	man/validator-validate.md \
	man/validator-blob.md \
	man/validator-dracut.md

MAN5PAGES=\
	man/validator-config.md

MANPAGES=${MAN1PAGES} ${MAN5PAGES}

if ENABLE_MAN

man/%.1: man/%.md
	mkdir -p man
	${MD2MAN} -in $^ -out $@

man/%.5: man/%.md
	mkdir -p man
	${MD2MAN} -in $^ -out $@

man1_MANS = $(MAN1PAGES:.md=.1)
man5_MANS = $(MAN5PAGES:.md=.5)

CLEANFILES = ${man1_MANS}  ${man5_MANS}

endif

if BUILDOPT_DRACUT
# Not using $(libdir) here is intentional, dracut modules go in prefix/lib
dracutmoddir = $(prefix)/lib/dracut/modules.d/98validator
dracutmod_SCRIPTS = dracut/module-setup.sh
dracutmod_DATA = dracut/validator-boot.service

install-exec-hook:
	mkdir -p $(DESTDIR)$(prefix)/lib/validator/boot.d
	mkdir -p $(DESTDIR)$(sysconfdir)/validator/boot.d
	mkdir -p $(DESTDIR)$(prefix)/lib/validator/keys
	mkdir -p $(DESTDIR)$(sysconfdir)/validator/keys
endif

AM_TESTS_ENVIRONMENT = \
	BUILDDIR=$(builddir) \
	SRCDIR=$(top_srcdir)

test_scripts = \
	test.sh

TESTS = test.sh

TEST_ASSETS=\
	test-assets/content/file1.txt.sig \
	test-assets/content/file2.txt.sig \
	test-assets/content/symlink1.sig \
	test-assets/content/dir/file3.txt.sig \
	test-assets/content/dir/symlink2.sig \
	test-assets/public.der \
	test-assets/secret.pem

EXTRA_DIST=\
	dracut/validator-boot.service \
	dracut/module-setup.sh \
	$(TEST_ASSETS) \
	validator.spec.in \
	validator.spec \
	test.sh \
	$(MANPAGES)
