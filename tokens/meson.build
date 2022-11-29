libcryptsetup_token_sym_path = join_paths(meson.current_source_dir(), 'libcryptsetup-token.sym')

token_link_args = [
    '-Wl,--version-script=' +
    libcryptsetup_token_sym_path,
]

subdir('ssh')
