bin_PROGRAMS = validator

.PHONY: clang-format
clang-format:
	git ls-files '**.c' '**.h' | xargs clang-format -i

AM_CFLAGS = $(DEPS_CFLAGS) $(WARN_CFLAGS) -I$(top_srcdir)/

validator_SOURCES = main.c main.h sign.c validate.c utils.c utils.h
validator_LDADD =  $(DEPS_LIBS)
