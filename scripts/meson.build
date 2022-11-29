if tmpfilesdir != ''
    cryptsetup_conf = configure_file(
        input: 'cryptsetup.conf.in',
        output: 'cryptsetup.conf',
        configuration: conf,
        install_dir: tmpfilesdir)
endif
