// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - setup cryptographic volumes for dm-crypt
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include "cryptsetup.h"
#include <signal.h>

/* interrupt handling */
volatile int quit = 0;
static int signals_blocked = 0;

static void int_handler(int sig __attribute__((__unused__)))
{
	quit++;
}

int tools_signals_blocked(void)
{
	return signals_blocked;
}

void set_int_block(int block)
{
	sigset_t signals_open;

	log_dbg("%slocking interruption on signal.", block ? "B" : "Unb");

	sigemptyset(&signals_open);
	sigaddset(&signals_open, SIGINT);
	sigaddset(&signals_open, SIGTERM);
	sigprocmask(block ? SIG_SETMASK : SIG_UNBLOCK, &signals_open, NULL);
	signals_blocked = block;
	quit = 0;
}

void set_int_handler(int block)
{
	struct sigaction sigaction_open;

	log_dbg("Installing SIGINT/SIGTERM handler.");
	memset(&sigaction_open, 0, sizeof(struct sigaction));
	sigaction_open.sa_handler = int_handler;
	sigaction(SIGINT, &sigaction_open, 0);
	sigaction(SIGTERM, &sigaction_open, 0);
	set_int_block(block);
}

void check_signal(int *r)
{
	if (quit && !*r)
		*r = -EINTR;
}

void tool_log(int level, const char *msg, void *usrptr)
{
	struct tools_log_params *params = (struct tools_log_params *)usrptr;

	switch (level) {

	case CRYPT_LOG_NORMAL:
		fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_VERBOSE:
		if (params && params->verbose)
			fprintf(stdout, "%s", msg);
		break;
	case CRYPT_LOG_ERROR:
		fprintf(stderr, "%s", msg);
		break;
	case CRYPT_LOG_DEBUG_JSON:
	case CRYPT_LOG_DEBUG:
		if (params && params->debug)
			fprintf(stdout, "# %s", msg);
		break;
	}
}

void quiet_log(int level, const char *msg, void *usrptr)
{
	struct tools_log_params *params = (struct tools_log_params *)usrptr;

	if ((!params || !params->verbose) && (level == CRYPT_LOG_ERROR || level == CRYPT_LOG_NORMAL))
		return;
	tool_log(level, msg, usrptr);
}

static int _dialog(const char *msg, void *usrptr, int default_answer)
{
	const char *fail_msg = (const char *)usrptr;
	char *answer = NULL;
	size_t size = 0;
	int r = default_answer, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (isatty(STDIN_FILENO)) {
		log_std(_("\nWARNING!\n========\n"));
		/* TRANSLATORS: User must type "YES" (in capital letters), do not translate this word. */
		log_std(_("%s\n\nAre you sure? (Type 'yes' in capital letters): "), msg);
		fflush(stdout);
		if(getline(&answer, &size, stdin) == -1) {
			r = 0;
			/* Aborted by signal */
			if (!quit)
				log_err(_("Error reading response from terminal."));
			else
				log_dbg("Query interrupted on signal.");
		} else {
			r = !strcmp(answer, "YES\n");
			if (!r && fail_msg)
				log_err("%s", fail_msg);
		}
	}

	if (block && !quit)
		set_int_block(1);

	free(answer);
	return r;
}

int yesDialog(const char *msg, void *usrptr)
{
	return _dialog(msg, usrptr, 1);
}

int noDialog(const char *msg, void *usrptr)
{
	return _dialog(msg, usrptr, 0);
}

void show_status(int errcode)
{
	char *crypt_error;

	if (!errcode) {
		log_verbose(_("Command successful."));
		return;
	}

	if (errcode < 0)
		errcode = translate_errno(errcode);

	if (errcode == 1)
		crypt_error = _("wrong or missing parameters");
	else if (errcode == 2)
		crypt_error = _("no permission or bad passphrase");
	else if (errcode == 3)
		crypt_error = _("out of memory");
	else if (errcode == 4)
		crypt_error = _("wrong device or file specified");
	else if (errcode == 5)
		crypt_error = _("device already exists or device is busy");
	else
		crypt_error = _("unknown error");

	log_verbose(_("Command failed with code %i (%s)."), -errcode, crypt_error);
}

const char *uuid_or_device(const char *spec)
{
	static char device[PATH_MAX];
	char s, *ptr;
	int i = 0, uuid_len = 5;

	/* Check if it is correct UUID=<LUKS_UUID> format */
	if (spec && !strncmp(spec, "UUID=", uuid_len)) {
		strcpy(device, "/dev/disk/by-uuid/");
		ptr = &device[strlen(device)];
		i = uuid_len;
		while ((s = spec[i++]) && i < (PATH_MAX - 13)) {
			if (!isxdigit(s) && s != '-')
				return spec; /* Bail it out */
			if (isalpha(s))
				s = tolower(s);
			*ptr++ = s;
		}
		*ptr = '\0';
		return device;
	}

	return spec;
}

__attribute__ ((noreturn)) void usage(poptContext popt_context,
					     int exitcode, const char *error,
					     const char *more)
{
	poptPrintUsage(popt_context, stderr, 0);
	if (error)
		log_err("%s: %s", more, error);
	tools_cleanup();
	poptFreeContext(popt_context);
	exit(exitcode);
}

void dbg_version_and_cmd(int argc, const char **argv)
{
	int i;

	log_std("# %s %s processing \"", PACKAGE_NAME, PACKAGE_VERSION);
	for (i = 0; i < argc; i++) {
		if (i)
			log_std(" ");
		log_std("%s", argv[i]);
	}
	log_std("\"\n");
}

/* Translate exit code to simple codes */
int translate_errno(int r)
{
	switch (r) {
	case 0: 	r = EXIT_SUCCESS; break;
	case -EEXIST:
	case -EBUSY:	r = 5; break;
	case -ENOTBLK:
	case -ENODEV:	r = 4; break;
	case -ENOMEM:	r = 3; break;
	case -EPERM:	r = 2; break;
	case -EINVAL:
	case -ENOENT:
	case -ENOSYS:
	default:	r = EXIT_FAILURE;
	}
	return r;
}

void tools_keyslot_msg(int keyslot, crypt_object_op op)
{
	if (keyslot < 0)
		return;

	if (op == CREATED)
		log_verbose(_("Key slot %i created."), keyslot);
	else if (op == UNLOCKED)
		log_verbose(_("Key slot %i unlocked."), keyslot);
	else if (op == REMOVED)
		log_verbose(_("Key slot %i removed."), keyslot);
}

void tools_token_msg(int token, crypt_object_op op)
{
	if (token < 0)
		return;

	if (op == CREATED)
		log_verbose(_("Token %i created."), token);
	else if (op == REMOVED)
		log_verbose(_("Token %i removed."), token);
}

void tools_token_error_msg(int error, const char *type, int token, bool pin_provided)
{
	if (error >= 0)
		return;

	if (error == -ENOANO) {
		if (pin_provided)
			log_verbose(_("No token could be unlocked with this PIN."));
		else if (token != CRYPT_ANY_TOKEN)
			log_verbose(_("Token %i requires PIN."), token);
		else if (type)
			log_verbose(_("Token (type %s) requires PIN."), type);
	} else if (error == -EPERM) {
		if (token != CRYPT_ANY_TOKEN)
			log_verbose(_("Token %i cannot unlock assigned keyslot(s) (wrong keyslot passphrase)."), token);
		else if (type)
			log_verbose(_("Token (type %s) cannot unlock assigned keyslot(s) (wrong keyslot passphrase)."), type);
	} if (error == -EAGAIN) {
		if (token != CRYPT_ANY_TOKEN)
			log_verbose(_("Token %i requires additional missing resource."), token);
		else if (type)
			log_verbose(_("Token (type %s) requires additional missing resource."), type);
	} if (error == -ENOENT) {
		if (type)
			log_verbose(_("No usable token (type %s) is available."), type);
		else
			log_verbose(_("No usable token is available."));
	}
}

/*
 * Device size string parsing, suffixes:
 * s|S - 512 bytes sectors
 * k  |K  |m  |M  |g  |G  |t  |T   - 1024 base
 * kiB|KiB|miB|MiB|giB|GiB|tiB|TiB - 1024 base
 * kb |KB |mM |MB |gB |GB |tB |TB  - 1000 base
 */
int tools_string_to_size(const char *s, uint64_t *size)
{
	char *endp = NULL;
	size_t len;
	uint64_t mult_base, mult, tmp;

	*size = strtoull(s, &endp, 10);
	if (!isdigit(s[0]) ||
	    (errno == ERANGE && *size == ULLONG_MAX) ||
	    (errno != 0 && *size == 0))
		return -EINVAL;

	if (!endp || !*endp)
		return 0;

	len = strlen(endp);
	/* Allow "B" and "iB" suffixes */
	if (len > 3 ||
	   (len == 3 && (endp[1] != 'i' || endp[2] != 'B')) ||
	   (len == 2 && endp[1] != 'B'))
		return -EINVAL;

	if (len == 1 || len == 3)
		mult_base = 1024;
	else
		mult_base = 1000;

	mult = 1;
	switch (endp[0]) {
	case 's':
	case 'S': mult = 512;
		break;
	case 't':
	case 'T': mult *= mult_base;
		 /* Fall through */
	case 'g':
	case 'G': mult *= mult_base;
		 /* Fall through */
	case 'm':
	case 'M': mult *= mult_base;
		 /* Fall through */
	case 'k':
	case 'K': mult *= mult_base;
		break;
	default:
		return -EINVAL;
	}

	tmp = *size * mult;
	if (*size && (tmp / *size) != mult) {
		log_dbg("Device size overflow.");
		return -EINVAL;
	}

	*size = tmp;
	return 0;
}

/*
 * Keyfile - is standard input treated as a binary file (no EOL handling).
 */
int tools_is_stdin(const char *key_file)
{
	if (!key_file)
		return 1;

	return strcmp(key_file, "-") ? 0 : 1;
}

int tools_read_vk(const char *file, char **key, int keysize)
{
	int fd = -1, r = -EINVAL;

	if (keysize <= 0 || !key)
		return -EINVAL;

	*key = crypt_safe_alloc(keysize);
	if (!*key)
		return -ENOMEM;

	fd = open(file, O_RDONLY);
	if (fd == -1) {
		log_err(_("Cannot read keyfile %s."), file);
		goto out;
	}

	if (read_buffer(fd, *key, keysize) != keysize) {
		log_err(_("Cannot read %d bytes from keyfile %s."), keysize, file);
		goto out;
	}
	r = 0;
out:
	if (fd != -1)
		close(fd);

	if (r) {
		crypt_safe_free(*key);
		*key = NULL;
	}

	return r;
}

int tools_write_mk(const char *file, const char *key, int keysize)
{
	int fd, r = -EINVAL;

	if (keysize <= 0 || !key)
		return -EINVAL;

	fd = open(file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (fd < 0) {
		log_err(_("Cannot open keyfile %s for write."), file);
		return r;
	}

	if (write_buffer(fd, key, keysize) == keysize)
		r = 0;
	else
		log_err(_("Cannot write to keyfile %s."), file);

	close(fd);
	return r;
}

void tools_package_version(const char *name, bool use_pwlibs)
{
	bool udev = false, blkid = false, keyring = false, fips = false,
	     kernel_capi = false, pwquality = false, passwdqc = false,
	     hw_opal = false;
#if USE_UDEV
	udev = true;
#endif
#if HAVE_BLKID
	blkid = true;
#endif
#if KERNEL_KEYRING
	keyring = true;
#endif
#if ENABLE_FIPS
	fips = true;
#endif
#if ENABLE_AF_ALG
	kernel_capi = true;
#endif
#if ENABLE_PWQUALITY
	pwquality = true;
#elif ENABLE_PASSWDQC
	passwdqc = true;
#endif
#if HAVE_HW_OPAL
	hw_opal = true;
#endif
	log_std("%s %s flags: %s%s%s%s%s%s%s%s\n", name, PACKAGE_VERSION,
		udev ?	"UDEV " : "",
		blkid ? "BLKID " : "",
		keyring ? "KEYRING " : "",
		fips ? "FIPS " : "",
		kernel_capi ? "KERNEL_CAPI " : "",
		pwquality && use_pwlibs ? "PWQUALITY " : "",
		passwdqc && use_pwlibs ? "PASSWDQC " : "",
		hw_opal ? "HW_OPAL " : "");
}

int tools_check_newname(const char *name)
{
	if (!name)
		return 0;

	if (strlen(name) >= DM_NAME_LEN) {
		log_err(_("Name is too long."));
		return -EINVAL;
	} else if (strchr(name, '/')) {
		log_err(_("Name must not contain '/' character."));
		return -EINVAL;
	}

	return 0;
}
