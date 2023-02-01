EXTRA_DIST = README.md oss-fuzz-build.sh
dist_noinst_DATA = \
	LUKS2.proto \
	LUKS2_plain_JSON.proto \
	crypt2_load_fuzz.dict \
	crypt2_load_ondisk_fuzz.dict \
	crypt2_load_proto_plain_json_fuzz.dict \
	unpoison-mutated-buffers-from-libfuzzer.patch
CLEANFILES = \
	LUKS2.pb.h \
	LUKS2.pb.cc \
	LUKS2_plain_JSON.pb.h \
	LUKS2_plain_JSON.pb.cc

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

LUKS2.pb.h: LUKS2.proto
	 $(DEPS_PATH)/bin/protoc LUKS2.proto --cpp_out=.
LUKS2.pb.cc: LUKS2.pb.h

LUKS2_plain_JSON.pb.h: LUKS2_plain_JSON.proto
	 $(DEPS_PATH)/bin/protoc LUKS2_plain_JSON.proto --cpp_out=.
LUKS2_plain_JSON.pb.cc: LUKS2_plain_JSON.pb.h

crypt2_load_proto_fuzz-crypt2_load_proto_fuzz.$(OBJEXT): LUKS2.pb.cc
crypt2_load_proto_plain_json_fuzz-crypt2_load_proto_plain_json_fuzz.$(OBJEXT): LUKS2_plain_JSON.pb.cc

nodist_crypt2_load_proto_fuzz_SOURCES = LUKS2.pb.h LUKS2.pb.cc
crypt2_load_proto_fuzz_SOURCES = FuzzerInterface.h \
	crypt2_load_proto_fuzz.cc \
	proto_to_luks2_converter.h \
	proto_to_luks2_converter.cc
crypt2_load_proto_fuzz_LDADD = \
	../../libcryptsetup.la \
	../../libcrypto_backend.la \
	-L$(DEPS_PATH)/lib -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf
crypt2_load_proto_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) $(SANITIZER)
crypt2_load_proto_fuzz_CXXFLAGS = $(AM_CXXFLAGS) \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/tests/fuzz \
	-I$(DEPS_PATH)/include \
	-I$(DEPS_PATH)/include/libprotobuf-mutator -I$(DEPS_PATH)/include/libprotobuf-mutator/src

nodist_crypt2_load_proto_plain_json_fuzz_SOURCES = LUKS2_plain_JSON.pb.h LUKS2_plain_JSON.pb.cc
crypt2_load_proto_plain_json_fuzz_SOURCES = FuzzerInterface.h \
	crypt2_load_proto_plain_json_fuzz.cc \
	json_proto_converter.h \
	json_proto_converter.cc \
	plain_json_proto_to_luks2_converter.h \
	plain_json_proto_to_luks2_converter.cc
crypt2_load_proto_plain_json_fuzz_LDADD = \
	../../libcryptsetup.la \
	../../libcrypto_backend.la \
	-L$(DEPS_PATH)/lib -lprotobuf-mutator-libfuzzer -lprotobuf-mutator -lprotobuf
crypt2_load_proto_plain_json_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) $(SANITIZER)
crypt2_load_proto_plain_json_fuzz_CXXFLAGS = $(AM_CXXFLAGS) \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/tests/fuzz \
	-I$(DEPS_PATH)/include \
	-I$(DEPS_PATH)/include/libprotobuf-mutator -I$(DEPS_PATH)/include/libprotobuf-mutator/src

nodist_proto_to_luks2_SOURCES = LUKS2.pb.h LUKS2.pb.cc
proto_to_luks2_SOURCES = \
	proto_to_luks2.cc \
	proto_to_luks2_converter.h \
	proto_to_luks2_converter.cc
proto_to_luks2_LDADD = ../../libcryptsetup.la ../../libcrypto_backend.la -L$(DEPS_PATH)/lib -lprotobuf
proto_to_luks2_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer-no-link $(SANITIZER)
proto_to_luks2_CXXFLAGS = $(AM_CXXFLAGS) \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/tests/fuzz \
	-I$(DEPS_PATH)/include

nodist_plain_json_proto_to_luks2_SOURCES = LUKS2_plain_JSON.pb.h LUKS2_plain_JSON.pb.cc
plain_json_proto_to_luks2_SOURCES = \
	plain_json_proto_to_luks2.cc \
	plain_json_proto_to_luks2_converter.h \
	plain_json_proto_to_luks2_converter.cc \
	json_proto_converter.h \
	json_proto_converter.cc
plain_json_proto_to_luks2_LDADD = ../../libcryptsetup.la ../../libcrypto_backend.la -L$(DEPS_PATH)/lib -lprotobuf
plain_json_proto_to_luks2_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer-no-link $(SANITIZER)
plain_json_proto_to_luks2_CXXFLAGS = $(AM_CXXFLAGS) \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/tests/fuzz \
	-I$(DEPS_PATH)/include

if ENABLE_FUZZ_TARGETS
noinst_PROGRAMS = \
	crypt2_load_fuzz \
	crypt2_load_ondisk_fuzz \
	crypt2_load_proto_fuzz \
	crypt2_load_proto_plain_json_fuzz \
	proto_to_luks2 \
	plain_json_proto_to_luks2

fuzz-targets: test-environment $(noinst_PROGRAMS)
.PHONY: fuzz-targets
endif
