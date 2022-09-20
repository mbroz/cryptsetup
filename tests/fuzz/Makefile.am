CLEANFILES = LUKS2.pb.h LUKS2.pb.cc

clean-local:
	-rm -rf LUKS2.pb.h LUKS2.pb.cc

TESTS = crypt2_load_fuzz crypt_load_fuzz

LIB_FUZZING_ENGINE := $(if $(LIB_FUZZING_ENGINE),$(LIB_FUZZING_ENGINE),"-fsanitize=fuzzer")

crypt2_load_fuzz_SOURCES = crypt2_load_fuzz.cc common.c
crypt2_load_fuzz_LDADD  = ../../libcryptsetup.la ../../libcrypto_backend.la
crypt2_load_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) -static
crypt2_load_fuzz_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz -fsanitize=fuzzer-no-link
crypt2_load_fuzz_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz -fsanitize=fuzzer-no-link

generate_proto: LUKS2.proto
	@protoc LUKS2.proto --cpp_out=.
	@protoc LUKS2_plain_JSON.proto --cpp_out=.
LUKS2.pb.h: generate_proto
LUKS2.pb.cc: generate_proto
LUKS2_plain_JSON.pb.cc: generate_proto
LUKS2_plain_JSON.pb.h: generate_proto

BUILT_SOURCES = LUKS2.pb.h LUKS2.pb.cc LUKS2_plain_JSON.pb.h LUKS2_plain_JSON.pb.cc

crypt2_load_proto_fuzz_SOURCES = crypt2_load_proto_fuzz.cc common.c LUKS2.pb.cc proto_to_luks2_converter.cc
crypt2_load_proto_fuzz_LDADD = \
	../../libcryptsetup.la		\
	../../libcrypto_backend.la	\
	@LIBPROTOBUF_MUTATOR_LIBS@	\
	@PROTOBUF_LIBS@
crypt2_load_proto_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) -static
crypt2_load_proto_fuzz_CFLAGS = -fsanitize=fuzzer-no-link
crypt2_load_proto_fuzz_CXXFLAGS = \
	$(AM_CXXFLAGS)			\
	-I$(top_srcdir)/lib		\
	-I$(top_srcdir)/tests/fuzz	\
	-fsanitize=fuzzer-no-link	\
	@LIBPROTOBUF_MUTATOR_CFLAGS@

crypt2_load_proto_plain_json_fuzz_SOURCES = crypt2_load_proto_plain_json_fuzz.cc common.c LUKS2_plain_JSON.pb.cc json_proto_converter.cc plain_json_proto_to_luks2_converter.cc
crypt2_load_proto_plain_json_fuzz_LDADD = \
	../../libcryptsetup.la		\
	../../libcrypto_backend.la	\
	@LIBPROTOBUF_MUTATOR_LIBS@	\
	@PROTOBUF_LIBS@
crypt2_load_proto_plain_json_fuzz_LDFLAGS = $(AM_LDFLAGS) $(LIB_FUZZING_ENGINE) -static
crypt2_load_proto_plain_json_fuzz_CFLAGS = -fsanitize=fuzzer-no-link
crypt2_load_proto_plain_json_fuzz_CXXFLAGS = \
	$(AM_CXXFLAGS)			\
	-I$(top_srcdir)/lib		\
	-I$(top_srcdir)/tests/fuzz	\
	-fsanitize=fuzzer-no-link	\
	@LIBPROTOBUF_MUTATOR_CFLAGS@

proto_to_luks2_SOURCES = proto_to_luks2.cc common.c LUKS2.pb.cc proto_to_luks2_converter.cc
proto_to_luks2_LDADD = ../../libcryptsetup.la ../../libcrypto_backend.la @PROTOBUF_LIBS@
proto_to_luks2_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer-no-link -static
proto_to_luks2_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz
proto_to_luks2_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz

plain_json_proto_to_luks2_SOURCES = plain_json_proto_to_luks2.cc common.c LUKS2_plain_JSON.pb.cc plain_json_proto_to_luks2_converter.cc json_proto_converter.cc
plain_json_proto_to_luks2_LDADD = ../../libcryptsetup.la ../../libcrypto_backend.la @PROTOBUF_LIBS@
plain_json_proto_to_luks2_LDFLAGS = $(AM_LDFLAGS) -fsanitize=fuzzer-no-link -static
plain_json_proto_to_luks2_CFLAGS = $(AM_CFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz
plain_json_proto_to_luks2_CXXFLAGS = $(AM_CXXFLAGS) -I$(top_srcdir)/lib -I$(top_srcdir)/tests/fuzz

check_PROGRAMS = crypt2_load_fuzz crypt2_load_proto_fuzz crypt2_load_proto_plain_json_fuzz proto_to_luks2 plain_json_proto_to_luks2

clang-only:
	@test "$(CC)" == "clang" || (echo "Building fuzz targets is only supported using clang. Please set CC=clang CXX=clang++" && exit 1)
	@test "$(CXX)" == "clang++" || (echo "Building fuzz targets is only supported using clang. Please set CC=clang CXX=clang++" && exit 1)

fuzz-targets: clang-only $(check_PROGRAMS)
