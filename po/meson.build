if get_option('nls')
    i18n = import('i18n')
    i18n.gettext(meson.project_name(),
        preset: 'glib',
        data_dirs: '.',
        install: true)
endif
