/*
 * LUKS - Linux Unified Key Setup, keyslot unlock helpers
 *
 * Copyright (C) 2022-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2023 Ondrej Kozina
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef KEYSLOT_CONTEXT_H
#define KEYSLOT_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "internal.h"

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

/* crypt_keyslot_context */
struct crypt_keyslot_context {
	int type;

	union {
	struct {
		const char *passphrase;
		size_t passphrase_size;
	} p;
	struct {
		const char *keyfile;
		uint64_t keyfile_offset;
		size_t keyfile_size;
	} kf;
	struct {
		int id;
		const char *type;
		const char *pin;
		size_t pin_size;
		void *usrptr;
	} t;
	struct {
		const char *volume_key;
		size_t volume_key_size;
	} k;
	struct {
		const char *volume_key;
		size_t volume_key_size;
		const char *signature;
		size_t signature_size;
	} ks;
	struct {
		const char *key_description;
	} kr;
	struct {
		const char *key_description;
	} vk_kr;
	} u;

	int error;

	char *i_passphrase;
	size_t i_passphrase_size;
	char *i_volume_key;
	size_t i_volume_key_size;

	keyslot_context_get_key			get_luks2_key;
	keyslot_context_get_volume_key		get_luks1_volume_key;
	keyslot_context_get_volume_key		get_luks2_volume_key;
	keyslot_context_get_generic_volume_key	get_plain_volume_key;
	keyslot_context_get_generic_volume_key	get_bitlk_volume_key;
	keyslot_context_get_generic_volume_key	get_fvault2_volume_key;
	keyslot_context_get_generic_signed_key	get_verity_volume_key;
	keyslot_context_get_generic_volume_key	get_integrity_volume_key;
	keyslot_context_get_passphrase		get_passphrase;
};

void crypt_keyslot_context_destroy_internal(struct crypt_keyslot_context *method);

void crypt_keyslot_unlock_by_key_init_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size);

void crypt_keyslot_unlock_by_signed_key_init_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size);

void crypt_keyslot_unlock_by_passphrase_init_internal(struct crypt_keyslot_context *kc,
	const char *passphrase,
	size_t passphrase_size);

void crypt_keyslot_unlock_by_keyfile_init_internal(struct crypt_keyslot_context *kc,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset);

void crypt_keyslot_unlock_by_token_init_internal(struct crypt_keyslot_context *kc,
	int token,
	const char *type,
	const char *pin,
	size_t pin_size,
	void *usrptr);

void crypt_keyslot_unlock_by_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description);

void crypt_keyslot_unlock_by_vk_in_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description);

const char *keyslot_context_type_string(const struct crypt_keyslot_context *kc);

#endif /* KEYSLOT_CONTEXT_H */
