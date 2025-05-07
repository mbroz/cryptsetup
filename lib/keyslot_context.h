// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup, keyslot unlock helpers
 *
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2025 Ondrej Kozina
 */

#ifndef KEYSLOT_CONTEXT_H
#define KEYSLOT_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "internal.h"

struct bitlk_metadata;
struct fvault2_params;

typedef int (*keyslot_context_get_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	int segment,
	struct volume_key **r_vk);

typedef int (*keyslot_context_get_volume_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk);

typedef int (*keyslot_context_get_generic_volume_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	struct volume_key **r_vk);

typedef int (*keyslot_context_get_bitlk_volume_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct bitlk_metadata *params,
	struct volume_key **r_vk);

typedef int (*keyslot_context_get_fvault2_volume_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct fvault2_params *params,
	struct volume_key **r_vk);


typedef int (*keyslot_context_get_generic_signed_key) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	struct volume_key **r_vk,
	struct volume_key **r_signature);

typedef int (*keyslot_context_get_passphrase) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const char **r_passphrase,
	size_t *r_passphrase_size);

typedef void (*keyslot_context_free) (
	struct crypt_keyslot_context *kc);

typedef int (*keyslot_context_get_key_size) (
	struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	size_t *r_key_size);

#define KC_VERSION_BASIC          UINT8_C(1)
#define KC_VERSION_SELF_CONTAINED UINT8_C(2)

/* crypt_keyslot_context */
struct crypt_keyslot_context {
	int type;

	/* versions:
	 * v1: All passed pointers (e.g.: type, passphrase, keyfile,...) must
	 *     be valid after ctx initialization.
	 * v2: Fully self-contained
	 */
	uint8_t version;

	union {
	struct {
		const char *passphrase;
		size_t passphrase_size;
	} p;
	struct {
		const char *keyfile;
		char *i_keyfile;
		uint64_t keyfile_offset;
		size_t keyfile_size;
	} kf;
	struct {
		int id;
		const char *type;
		char *i_type;
		const char *pin;
		char *i_pin;
		size_t pin_size;
		void *usrptr;
	} t;
	struct {
		const char *volume_key;
		size_t volume_key_size;
		struct volume_key *i_vk;
	} k;
	struct {
		const char *volume_key;
		size_t volume_key_size;
		struct volume_key *i_vk;
		const char *signature;
		size_t signature_size;
		struct volume_key *i_vk_sig;
	} ks;
	struct {
		const char *key_description;
		char *i_key_description;
	} kr;
	struct {
		const char *key_description;
		char *i_key_description;
		size_t i_key_size;
	} vk_kr;
	} u;

	int error;

	char *i_passphrase;
	size_t i_passphrase_size;

	keyslot_context_get_key			get_luks2_key;
	keyslot_context_get_volume_key		get_luks1_volume_key;
	keyslot_context_get_volume_key		get_luks2_volume_key;
	keyslot_context_get_generic_volume_key	get_plain_volume_key;
	keyslot_context_get_bitlk_volume_key	get_bitlk_volume_key;
	keyslot_context_get_fvault2_volume_key	get_fvault2_volume_key;
	keyslot_context_get_generic_signed_key	get_verity_volume_key;
	keyslot_context_get_generic_volume_key	get_integrity_volume_key;
	keyslot_context_get_passphrase		get_passphrase;
	keyslot_context_get_key_size		get_key_size;
	keyslot_context_free			context_free;
};

void crypt_keyslot_context_destroy_internal(struct crypt_keyslot_context *method);

void crypt_keyslot_context_init_by_key_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size);

void crypt_keyslot_context_init_by_signed_key_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size);

void crypt_keyslot_context_init_by_passphrase_internal(struct crypt_keyslot_context *kc,
	const char *passphrase,
	size_t passphrase_size);

void crypt_keyslot_context_init_by_keyfile_internal(struct crypt_keyslot_context *kc,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset);

void crypt_keyslot_context_init_by_token_internal(struct crypt_keyslot_context *kc,
	int token,
	const char *type,
	const char *pin,
	size_t pin_size,
	void *usrptr);

void crypt_keyslot_context_init_by_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description);

const char *keyslot_context_type_string(const struct crypt_keyslot_context *kc);

#endif /* KEYSLOT_CONTEXT_H */
