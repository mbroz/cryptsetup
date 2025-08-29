fs = import('fs')

adocfiles_common = [
    'common_options.adoc',
    'common_footer.adoc',
]

manpage_tuples_to_build = []
manpage_tuples_all = []

# tuple with adoc file and generated aliases
cryptsetup_manpages = [
    [
        'cryptsetup.8.adoc',
        [],
    ],
    [
        'cryptsetup-open.8.adoc',
        [
            'cryptsetup-create.8',
            'cryptsetup-plainOpen.8',
            'cryptsetup-luksOpen.8',
            'cryptsetup-loopaesOpen.8',
            'cryptsetup-tcryptOpen.8',
            'cryptsetup-bitlkOpen.8',
            'cryptsetup-fvault2Open.8',
        ],
    ],
    [
        'cryptsetup-close.8.adoc',
        [],
    ],
    [
        'cryptsetup-reencrypt.8.adoc',
        [],
    ],
    [
        'cryptsetup-status.8.adoc',
        [],
    ],
    [
        'cryptsetup-resize.8.adoc',
        [],
    ],
    [
        'cryptsetup-refresh.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksFormat.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksSuspend.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksResume.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksAddKey.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksRemoveKey.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksConvertKey.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksKillSlot.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksChangeKey.8.adoc',
        [],
    ],
    [
        'cryptsetup-erase.8.adoc',
        [
            'cryptsetup-luksErase.8',
        ],
    ],
    [
        'cryptsetup-luksUUID.8.adoc',
        [],
    ],
    [
        'cryptsetup-isLuks.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksDump.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksHeaderBackup.8.adoc',
        [],
    ],
    [
        'cryptsetup-luksHeaderRestore.8.adoc',
        [],
    ],
    [
        'cryptsetup-token.8.adoc',
        [],
    ],
    [
        'cryptsetup-convert.8.adoc',
        [],
    ],
    [
        'cryptsetup-config.8.adoc',
        [],
    ],
    [
        'cryptsetup-tcryptDump.8.adoc',
        [],
    ],
    [
        'cryptsetup-bitlkDump.8.adoc',
        [],
    ],
    [
        'cryptsetup-fvault2Dump.8.adoc',
        [],
    ],
    [
        'cryptsetup-repair.8.adoc',
        [],
    ],
    [
        'cryptsetup-benchmark.8.adoc',
        [],
    ],
]

veritysetup_manpages = [
    [
        'veritysetup.8.adoc',
        [],
    ],
]
integritysetup_manpages = [
    [
        'integritysetup.8.adoc',
        [],
    ],
]
sshplugin_manpages = [
    [
        'cryptsetup-ssh.8.adoc',
        [],
    ],
]

if get_option('cryptsetup')
    manpage_tuples_to_build += cryptsetup_manpages
endif
manpage_tuples_all += cryptsetup_manpages
if get_option('veritysetup')
    manpage_tuples_to_build += veritysetup_manpages
endif
manpage_tuples_all += veritysetup_manpages
if get_option('integritysetup')
    manpage_tuples_to_build += integritysetup_manpages
endif
manpage_tuples_all += integritysetup_manpages
if get_option('ssh-token')
    manpage_tuples_to_build += sshplugin_manpages
endif
manpage_tuples_all += sshplugin_manpages

adocfiles_all = []
foreach tuple : manpage_tuples_all
    adocfiles_all += tuple[0]
endforeach

prebuilt_manpages_exist = true
foreach manpage_tuple : manpage_tuples_to_build
    adocfile = manpage_tuple[0]
    aliases = manpage_tuple[1]
    manfile = fs.replace_suffix(adocfile, '')

    prebuilt_manpages_exist = prebuilt_manpages_exist and fs.exists(manfile)

    foreach alias : aliases
        prebuilt_manpages_exist = prebuilt_manpages_exist and fs.exists(alias)
    endforeach
endforeach

built_manpages = []

if use_asciidoc
    meson.add_dist_script(find_program('meson_dist_convert.sh'),
        asciidoc, meson.project_version(), adocfiles_all)

    foreach manpage_tuple : manpage_tuples_to_build
        adocfile = manpage_tuple[0]
        aliases = manpage_tuple[1]

        mandir = join_paths(get_option('prefix'), get_option('mandir'), 'man8')
        manfile = fs.replace_suffix(adocfile, '')

        built_manpages += custom_target(manfile,
            command: [
                asciidoc,
                '-b', 'manpage',
                '--failure-level', 'ERROR',
                '-a', 'release-version=@0@'.format(
                    meson.project_version(),
                ),
                '-o', '@BASENAME@',
                '@INPUT@',
                '--destination-dir=@0@'.format(
                    meson.current_build_dir(),
                ),
                '--base-dir=@SOURCE_ROOT@',
            ],
            input: adocfile,
            depend_files: adocfiles_common,
            install: true,
            install_dir: mandir,
            output: [
                manfile,
            ] + aliases,
        )
    endforeach
else
    # use_asciidoc == false
    if prebuilt_manpages_exist
        message('Using prebuilt manpages.')
        foreach manpage_tuple : manpage_tuples_to_build
            adocfile = manpage_tuple[0]
            aliases = manpage_tuple[1]
            manfile = fs.replace_suffix(adocfile, '')

            install_man(manfile)
            foreach alias : aliases
                install_man(alias)
            endforeach
        endforeach
    else
        warning('Neither asciidoctor nor prebuilt manual pages found. Skipping manpage installation')
    endif
endif

man = custom_target(
    'man',
    output: 'man',
    depends: built_manpages,
    command: [
        nop_command,
    ])
