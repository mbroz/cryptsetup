// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Helper utilities for LUKS in cryptsetup
 *
 * Copyright (C) 2018-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2025 Milan Broz
 * Copyright (C) 2018-2025 Ondrej Kozina
 */

#ifndef UTILS_LUKS_H
#define UTILS_LUKS_H

#include <stdint.h>
#include <stdbool.h>

struct crypt_device;

const char *luksType(const char *type);

bool isLUKS1(const char *type);

bool isLUKS2(const char *type);

int verify_passphrase(int def);

void set_activation_flags(uint32_t *flags);

int set_pbkdf_params(struct crypt_device *cd, const char *dev_type);

int set_tries_tty(bool keyring);

int get_adjusted_key_size(const char *cipher, const char *cipher_mode, uint32_t keysize_bits,
			  uint32_t default_size_bits, int integrity_keysize);

int luksFormat(struct crypt_device **r_cd, struct crypt_keyslot_context **r_kc);

int reencrypt(int action_argc, const char **action_argv);

int reencrypt_luks1(const char *device);

int reencrypt_luks1_in_progress(const char *device);

int luks_init_keyslot_context(struct crypt_device *cd,
			      const char *msg,
			      bool verify, bool pwquality,
			      struct crypt_keyslot_context **r_kc);

int luks_try_token_unlock(struct crypt_device *cd,
			  int keyslot,
			  int token_id,
			  const char *activated_name,
			  const char *token_type,
			  uint32_t activate_flags,
			  int tries,
			  bool activation,
			  bool retry_with_pin,
			  struct crypt_keyslot_context **r_kc);

int luks_init_keyslot_contexts_by_volume_keys(struct crypt_device *cd,
					      const char *vk_file1,
					      const char *vk_file2,
					      int keysize1_bytes,
					      int keysize2_bytes,
					      const char *vk_in_keyring1,
					      const char *vk_in_keyring2,
					      struct crypt_keyslot_context **r_kc1,
					      struct crypt_keyslot_context **r_kc2);

void luks_check_keyslots(struct crypt_device *cd, const char *device);

#endif /* UTILS_LUKS_H */
