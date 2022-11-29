libargon2_sources = files(
    'blake2/blake2b.c',
    'argon2.c',
    'core.c',
    'encoding.c',
    'thread.c',
)

if use_internal_sse_argon2
    libargon2_sources += files(
        'opt.c',
    )
else
    libargon2_sources += files(
        'ref.c',
    )
endif

libargon2 = static_library('argon2',
    libargon2_sources,
    override_options : ['c_std=c89', 'optimization=3'],
    build_by_default : false,
    include_directories: include_directories(
        'blake2',
    ),
    dependencies : [
        threads,
    ])
