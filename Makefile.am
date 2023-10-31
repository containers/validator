bin_PROGRAMS = validator

.PHONY: clang-format
clang-format:
	git ls-files '**.c' '**.h' | xargs clang-format -i

AM_CFLAGS = $(DEPS_CFLAGS) $(WARN_CFLAGS) -I$(top_srcdir)/

validator_SOURCES = main.c main.h utils.c utils.h sign.c validate.c install.c blob.c
validator_LDADD =  $(DEPS_LIBS)

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
	$(TEST_ASSETS) \
	validator.spec.in \
	validator.spec \
	test.sh
