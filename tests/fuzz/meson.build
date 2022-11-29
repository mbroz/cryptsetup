if get_option('fuzz-targets')
    crypt2_load_fuzz = executable('crypt2_load_fuzz',
        [
            'crypt2_load_fuzz.cc',
        ],
        dependencies: [
            devmapper,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    crypt2_load_ondisk_fuzz = executable('crypt2_load_ondisk_fuzz',
        [
            'crypt2_load_ondisk_fuzz.cc',
        ],
        dependencies: [
            devmapper,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    luks2_generated = protoc_generator.process('LUKS2.proto')
    crypt2_load_proto_fuzz = executable('crypt2_load_proto_fuzz',
        [
            'crypt2_load_proto_fuzz.cc',
            'proto_to_luks2_converter.cc',
            luks2_generated,
        ],
        dependencies: [
            devmapper,
            protobuf,
            libprotobuf_mutator,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    luks2_plain_json_generated = protoc_generator.process('LUKS2_plain_JSON.proto')
    crypt2_load_proto_plain_fuzz = executable('crypt2_load_proto_plain_fuzz',
        [
            'crypt2_load_proto_plain_json_fuzz.cc',
            'json_proto_converter.cc',
            'plain_json_proto_to_luks2_converter.cc',
            luks2_plain_json_generated,
        ],
        dependencies: [
            devmapper,
            protobuf,
            libprotobuf_mutator,
            fuzzing_engine,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    proto_to_luks2 = executable('proto_to_luks2',
        [
            'proto_to_luks2.cc',
            'proto_to_luks2_converter.cc',
            luks2_generated,
        ],
        dependencies: [
            devmapper,
            protobuf,
            libprotobuf_mutator,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)

    plain_json_proto_to_luks2 = executable('plain_json_proto_to_luks2',
        [
            'plain_json_proto_to_luks2.cc',
            'plain_json_proto_to_luks2_converter.cc',
            'json_proto_converter.cc',
            luks2_plain_json_generated,
        ],
        dependencies: [
            devmapper,
            protobuf,
            libprotobuf_mutator,
        ],
        link_with: [
            libcryptsetup,
            libcrypto_backend,
            libutils_io,
        ],
        link_args: [
            link_args,
        ],
        include_directories: includes_tools)
endif
