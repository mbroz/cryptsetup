// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Helper utilities for LUKS2 features
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2025 Milan Broz
 * Copyright (C) 2018-2025 Ondrej Kozina
 */

#include "cryptsetup.h"
#include "cryptsetup_args.h"
#include "utils_luks.h"

extern const char *set_pbkdf;

const char *luksType(const char *type)
{
	if (type && !strcmp(type, "luks2"))
		return CRYPT_LUKS2;

	if (type && !strcmp(type, "luks1"))
		return CRYPT_LUKS1;

	if (type && !strcmp(type, "luks"))
		return CRYPT_LUKS; /* NULL */

	if (type && *type)
		return type;

	return CRYPT_LUKS; /* NULL */
}

bool isLUKS1(const char *type)
{
	return type && !strcmp(type, CRYPT_LUKS1);
}

bool isLUKS2(const char *type)
{
	/* OPAL just changes the driver, header format is identical, so overload */
	return type && (!strcmp(type, CRYPT_LUKS2));
}

int verify_passphrase(int def)
{
	/* Batch mode switch off verify - if not overridden by -y */
	if (ARG_SET(OPT_VERIFY_PASSPHRASE_ID))
		def = 1;
	else if (ARG_SET(OPT_BATCH_MODE_ID))
		def = 0;

	/* Non-tty input doesn't allow verify */
	if (def && !isatty(STDIN_FILENO)) {
		if (ARG_SET(OPT_VERIFY_PASSPHRASE_ID))
			log_err(_("Can't do passphrase verification on non-tty inputs."));
		def = 0;
	}

	return def;
}

void set_activation_flags(uint32_t *flags)
{
	if (ARG_SET(OPT_READONLY_ID))
		*flags |= CRYPT_ACTIVATE_READONLY;

	if (ARG_SET(OPT_ALLOW_DISCARDS_ID))
		*flags |= CRYPT_ACTIVATE_ALLOW_DISCARDS;

	if (ARG_SET(OPT_PERF_SAME_CPU_CRYPT_ID))
		*flags |= CRYPT_ACTIVATE_SAME_CPU_CRYPT;

	if (ARG_SET(OPT_PERF_SUBMIT_FROM_CRYPT_CPUS_ID))
		*flags |= CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS;

	if (ARG_SET(OPT_PERF_NO_READ_WORKQUEUE_ID))
		*flags |= CRYPT_ACTIVATE_NO_READ_WORKQUEUE;

	if (ARG_SET(OPT_PERF_NO_WRITE_WORKQUEUE_ID))
		*flags |= CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE;

	if (ARG_SET(OPT_PERF_HIGH_PRIORITY_ID))
		*flags |= CRYPT_ACTIVATE_HIGH_PRIORITY;

	if (ARG_SET(OPT_INTEGRITY_NO_JOURNAL_ID))
		*flags |= CRYPT_ACTIVATE_NO_JOURNAL;

	/* In persistent mode, we use what is set on command line */
	if (ARG_SET(OPT_PERSISTENT_ID))
		*flags |= CRYPT_ACTIVATE_IGNORE_PERSISTENT;

	/* Only for LUKS2 but ignored elsewhere */
	if (ARG_SET(OPT_TEST_PASSPHRASE_ID) &&
            (ARG_SET(OPT_KEY_SLOT_ID) || ARG_SET(OPT_UNBOUND_ID)))
		*flags |= CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY;

	if (ARG_SET(OPT_LINK_VK_TO_KEYRING_ID))
		*flags |= CRYPT_ACTIVATE_KEYRING_KEY;

	if (ARG_SET(OPT_SERIALIZE_MEMORY_HARD_PBKDF_ID))
		*flags |= CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF;

	/* Only for plain */
	if (ARG_SET(OPT_IV_LARGE_SECTORS_ID))
		*flags |= CRYPT_ACTIVATE_IV_LARGE_SECTORS;
}

int set_pbkdf_params(struct crypt_device *cd, const char *dev_type)
{
	const struct crypt_pbkdf_type *pbkdf_default;
	struct crypt_pbkdf_type pbkdf = {};

	pbkdf_default = crypt_get_pbkdf_default(dev_type);
	if (!pbkdf_default)
		return -EINVAL;

	pbkdf.type = set_pbkdf ?: pbkdf_default->type;
	pbkdf.hash = ARG_STR(OPT_HASH_ID) ?: pbkdf_default->hash;
	pbkdf.time_ms = ARG_UINT32(OPT_ITER_TIME_ID) ?: pbkdf_default->time_ms;
	if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
		pbkdf.max_memory_kb = ARG_UINT32(OPT_PBKDF_MEMORY_ID) ?: pbkdf_default->max_memory_kb;
		pbkdf.parallel_threads = ARG_UINT32(OPT_PBKDF_PARALLEL_ID) ?: pbkdf_default->parallel_threads;
	}

	if (ARG_SET(OPT_PBKDF_FORCE_ITERATIONS_ID)) {
		pbkdf.iterations = ARG_UINT32(OPT_PBKDF_FORCE_ITERATIONS_ID);
		pbkdf.time_ms = 0;
		pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
	}

	return crypt_set_pbkdf_type(cd, &pbkdf);
}

int set_tries_tty(bool keyring)
{
	if (keyring && ARG_SET(OPT_KEY_DESCRIPTION_ID))
		return 1;

	return (tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)) && isatty(STDIN_FILENO)) ? ARG_UINT32(OPT_TRIES_ID) : 1;
}

int get_adjusted_key_size(const char *cipher, const char *cipher_mode, uint32_t keysize_bits,
			  uint32_t default_size_bits, int integrity_keysize)
{
#if ENABLE_LUKS_ADJUST_XTS_KEYSIZE
	if (!keysize_bits && (!strncmp(cipher_mode, "xts-", 4) || !strncmp(cipher, "capi:xts(", 9))) {
		if (default_size_bits == 128)
			keysize_bits = 256;
		else if (default_size_bits == 256)
			keysize_bits = 512;
	}
#endif
	return (keysize_bits ?: default_size_bits) / 8 + integrity_keysize;
}

/*
 * FIXME: 4MiBs is max LUKS2 mda length (including binary header).
 * In future, read max allowed JSON size from config section.
 */
#define LUKS2_MAX_MDA_SIZE 0x400000
int tools_read_json_file(const char *file, char **json, size_t *json_size, bool batch_mode)
{
	ssize_t ret;
	int fd, block, r;
	void *buf = NULL;
	bool close_fd = false;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (tools_is_stdin(file)) {
		fd = STDIN_FILENO;
		log_dbg("STDIN descriptor JSON read requested.");
	} else {
		log_dbg("File descriptor JSON read requested.");
		fd = open(file, O_RDONLY);
		if (fd < 0) {
			log_err(_("Failed to open file %s in read-only mode."), file);
			r = -EINVAL;
			goto out;
		}
		close_fd = true;
	}

	buf = malloc(LUKS2_MAX_MDA_SIZE);
	if (!buf) {
		r = -ENOMEM;
		goto out;
	}

	if (isatty(fd) && !batch_mode)
		log_std(_("Provide valid LUKS2 token JSON:\n"));

	/* we expect JSON (string) */
	r = 0;
	ret = read_buffer_intr(fd, buf, LUKS2_MAX_MDA_SIZE - 1, &quit);
	if (ret < 0) {
		r = -EIO;
		log_err(_("Failed to read JSON file."));
		goto out;
	}
	check_signal(&r);
	if (r) {
		log_err(_("\nRead interrupted."));
		goto out;
	}

	*json_size = (size_t)ret;
	*json = buf;
	*(*json + ret) = '\0';
out:
	if (block && !quit)
		set_int_block(1);
	if (close_fd)
		close(fd);
	if (r && buf) {
		memset(buf, 0, LUKS2_MAX_MDA_SIZE);
		free(buf);
	}
	return r;
}

int tools_write_json_file(const char *file, const char *json)
{
	int block, fd, r;
	size_t json_len;
	ssize_t ret;

	if (!json || !(json_len = strlen(json)) || json_len >= LUKS2_MAX_MDA_SIZE)
		return -EINVAL;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (tools_is_stdin(file)) {
		fd = STDOUT_FILENO;
		log_dbg("STDOUT descriptor JSON write requested.");
	} else {
		log_dbg("File descriptor JSON write requested.");
		fd = open(file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	}

	if (fd < 0) {
		log_err(_("Failed to open file %s in write mode."), file ?: "");
		r = -EINVAL;
		goto out;
	}

	r = 0;
	ret = write_buffer_intr(fd, json, json_len, &quit);
	check_signal(&r);
	if (r) {
		log_err(_("\nWrite interrupted."));
		goto out;
	}
	if (ret < 0 || (size_t)ret != json_len) {
		log_err(_("Failed to write JSON file."));
		r = -EIO;
		goto out;
	}

	if (isatty(fd))
		(void) write_buffer_intr(fd, "\n", 1, &quit);
out:
	if (block && !quit)
		set_int_block(1);
	if (fd >=0 && fd != STDOUT_FILENO)
		close(fd);
	return r;
}

int luks_init_keyslot_context(struct crypt_device *cd,
			      const char *msg,
			      bool verify, bool pwquality,
			      struct crypt_keyslot_context **r_kc)
{
	char *password;
	size_t passwordLen;
	int r = -EINVAL;

	assert(cd);
	assert(r_kc);

	if (ARG_SET(OPT_KEY_DESCRIPTION_ID))
		r = crypt_keyslot_context_init_by_keyring(cd, ARG_STR(OPT_KEY_DESCRIPTION_ID), r_kc);
	else if (ARG_SET(OPT_KEY_FILE_ID) && !tools_is_stdin(ARG_STR(OPT_KEY_FILE_ID)))
		r = crypt_keyslot_context_init_by_keyfile(cd, ARG_STR(OPT_KEY_FILE_ID),
							  ARG_UINT32(OPT_KEYFILE_SIZE_ID),
							  ARG_UINT64(OPT_KEYFILE_OFFSET_ID), r_kc);
	else {
		r = tools_get_key(msg, &password, &passwordLen, ARG_UINT64(OPT_KEYFILE_OFFSET_ID),
				  ARG_UINT32(OPT_KEYFILE_SIZE_ID), ARG_STR(OPT_KEY_FILE_ID),
				  ARG_UINT32(OPT_TIMEOUT_ID), verify, pwquality, cd);
		if (r < 0)
			return r;
		r = crypt_keyslot_context_init_by_passphrase(cd, password, passwordLen, r_kc);
		crypt_safe_free(password);
	}

	return r;
}

int luks_try_token_unlock(struct crypt_device *cd,
			  int keyslot,
			  int token_id,
			  const char *activated_name,
			  const char *token_type,
			  uint32_t activate_flags,
			  int tries,
			  bool activation,
			  bool retry_with_pin,
			  struct crypt_keyslot_context **r_kc)
{
	int r;
	struct crypt_keyslot_context *kc;
	size_t pin_len;
	char msg[64], *pin = NULL;

	assert(tries >= 1);
	assert(token_id >= 0 || token_id == CRYPT_ANY_TOKEN);
	assert(keyslot >= 0 || keyslot == CRYPT_ANY_SLOT);

	r = crypt_keyslot_context_init_by_token(cd, token_id, token_type, NULL, 0, NULL, &kc);
	if (r < 0)
		return r;

	if (activation)
		r = crypt_activate_by_keyslot_context(cd, activated_name, keyslot, kc, CRYPT_ANY_SLOT, kc, activate_flags);
	else
		r = crypt_resume_by_keyslot_context(cd, activated_name, keyslot, kc);

	tools_keyslot_msg(r, UNLOCKED);
	tools_token_error_msg(r, token_type, token_id, false);

	/* Token requires PIN (-ENOANO). */
	if (r != -ENOANO || !retry_with_pin)
		goto out;

	if (token_id == CRYPT_ANY_TOKEN)
		r = snprintf(msg, sizeof(msg), _("Enter token PIN: "));
	else
		r = snprintf(msg, sizeof(msg), _("Enter token %d PIN: "), token_id);
	if (r < 0 || (size_t)r >= sizeof(msg)) {
		r = -EINVAL;
		goto out;
	}

	do {
		r = tools_get_key(msg, &pin, &pin_len, 0, 0, NULL,
				ARG_UINT32(OPT_TIMEOUT_ID), verify_passphrase(0), 0, cd);
		if (r < 0)
			break;

		r = crypt_keyslot_context_set_pin(cd, pin, pin_len, kc);
		crypt_safe_free(pin);
		if (r < 0)
			break;

		if (activation)
			r = crypt_activate_by_keyslot_context(cd, activated_name, keyslot,
							      kc, CRYPT_ANY_SLOT, NULL, activate_flags);
		else
			r = crypt_resume_by_keyslot_context(cd, activated_name, keyslot, kc);

		tools_keyslot_msg(r, UNLOCKED);
		tools_token_error_msg(r, token_type, token_id, true);
		check_signal(&r);
	} while (r == -ENOANO && (--tries > 0));
out:
	if (r >= 0 && r_kc)
		*r_kc = kc;
	else
		crypt_keyslot_context_free(kc);

	return r;
}

/* Initiates keyslot context(s) based on non-interactive input only */
int luks_init_keyslot_contexts_by_volume_keys(struct crypt_device *cd,
					      const char *vk_file1,
					      const char *vk_file2,
					      int keysize1_bytes,
					      int keysize2_bytes,
					      const char *vk_in_keyring1,
					      const char *vk_in_keyring2,
					      struct crypt_keyslot_context **r_kc1,
					      struct crypt_keyslot_context **r_kc2)
{
	int r = -EINVAL;
	char *vk_description = NULL, *key = NULL;
	struct crypt_keyslot_context *kc1 = NULL, *kc2 = NULL;

	assert(cd);
	assert(r_kc1);
	assert(r_kc2);

	if (vk_file1 && keysize1_bytes > 0) {
		r = tools_read_vk(vk_file1, &key, keysize1_bytes);
		if (r < 0)
			return r;

		r = crypt_keyslot_context_init_by_volume_key(cd, key, keysize1_bytes, &kc1);
		if (r < 0)
			goto out;
	}

	/* volume key in file takes precedence */
	if (vk_in_keyring1 && !kc1) {
		r = tools_parse_vk_description(vk_in_keyring1, &vk_description);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description, &kc1);
		if (r < 0)
			goto out;
	}

	if (vk_file2 && keysize2_bytes > 0) {
		crypt_safe_free(key);
		key = NULL;
		r = tools_read_vk(vk_file2, &key, keysize2_bytes);
		if (r < 0)
			goto out;

		r = crypt_keyslot_context_init_by_volume_key(cd, key, keysize2_bytes, &kc2);
		if (r < 0)
			goto out;
	}

	/* volume key in file takes precedence */
	if (vk_in_keyring2 && !kc2) {
		free(vk_description);
		vk_description = NULL;
		r = tools_parse_vk_description(vk_in_keyring2, &vk_description);
		if (r < 0)
			goto out;
		r = crypt_keyslot_context_init_by_vk_in_keyring(cd, vk_description, &kc2);
	}
out:
	crypt_safe_free(key);
	free(vk_description);

	if (r) {
		crypt_keyslot_context_free(kc1);
		crypt_keyslot_context_free(kc2);
	} else {
		*r_kc1 = kc1;
		*r_kc2 = kc2;
	}

	return r;
}
