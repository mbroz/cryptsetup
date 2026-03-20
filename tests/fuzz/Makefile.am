EXTRA_DIST = README.md oss-fuzz-build.sh

distclean-local:
	-rm -rf out build

LIB_FUZZING_ENGINE := $(if $(LIB_FUZZING_ENGINE),$(LIB_FUZZING_ENGINE),"-fsanitize=fuzzer")
SANITIZER := $(if $(SANITIZER),,"-fsanitize=address")

DEPS_PATH := $(top_srcdir)/tests/fuzz/build/static_lib_deps

crypt2_load_fuzz_SOURCES = FuzzerInterface.h crypt2_load_fuzz.cc
crypt2_load_fuzz_LDADD  = ../../libcryptsetup.la ../../libcrypto_backend.la -L$(DEPS_PATH)/lib
crypt2_load_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) $(SANITIZER)
crypt2_load_fuzz_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz

crypt2_load_ondisk_fuzz_SOURCES = FuzzerInterface.h crypt2_load_ondisk_fuzz.cc
crypt2_load_ondisk_fuzz_LDADD  = ../../libcryptsetup.la -L$(DEPS_PATH)/lib
crypt2_load_ondisk_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) $(SANITIZER)
crypt2_load_ondisk_fuzz_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz

test-environment-m:
	@ if test ! -d $(DEPS_PATH); then \
		echo "You need to build static libraries first; use oss-fuzz-build.sh script."; \
		exit 1; \
	fi
test-environment: | test-environment-m $(DEPS_PATH)

if ENABLE_FUZZ_TARGETS
noinst_PROGRAMS = \
	crypt2_load_fuzz \
	crypt2_load_ondisk_fuzz

fuzz-targets: test-environment $(noinst_PROGRAMS)
.PHONY: fuzz-targets
endif
