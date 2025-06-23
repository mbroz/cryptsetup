// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * LUKS - Linux Unified Key Setup, keyslot unlock helpers
 *
 * Copyright (C) 2022-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2022-2025 Ondrej Kozina
 */

#include <errno.h>

#include "bitlk/bitlk.h"
#include "fvault2/fvault2.h"
#include "luks1/luks.h"
#include "luks2/luks2.h"
#include "keyslot_context.h"

static int get_luks2_key_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	int segment,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
	assert(r_vk);

	r = LUKS2_keyslot_open(cd, keyslot, segment, kc->u.p.passphrase, kc->u.p.passphrase_size, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_luks1_volume_key_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
	assert(r_vk);

	r = LUKS_open_key_with_hdr(keyslot, kc->u.p.passphrase, kc->u.p.passphrase_size,
				   crypt_get_hdr(cd, CRYPT_LUKS1), r_vk, cd);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_luks2_volume_key_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	return get_luks2_key_by_passphrase(cd, kc, keyslot, CRYPT_DEFAULT_SEGMENT, r_vk);
}

static int get_bitlk_volume_key_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct bitlk_metadata *params,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
	assert(params);
	assert(r_vk);

	r = BITLK_get_volume_key(cd, kc->u.p.passphrase, kc->u.p.passphrase_size, params, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_fvault2_volume_key_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct fvault2_params *params,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
	assert(params);
	assert(r_vk);

	r = FVAULT2_get_volume_key(cd, kc->u.p.passphrase, kc->u.p.passphrase_size, params, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_passphrase_by_passphrase(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const char **r_passphrase,
	size_t *r_passphrase_size)
{
	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
	assert(r_passphrase);
	assert(r_passphrase_size);

	*r_passphrase = kc->u.p.passphrase;
	*r_passphrase_size = kc->u.p.passphrase_size;

	return 0;
}

static int get_passphrase_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const char **r_passphrase,
	size_t *r_passphrase_size)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);
	assert(r_passphrase);
	assert(r_passphrase_size);

	if (!kc->i_passphrase) {
		r = crypt_keyfile_device_read(cd, kc->u.kf.keyfile,
				       &kc->i_passphrase, &kc->i_passphrase_size,
				       kc->u.kf.keyfile_offset, kc->u.kf.keyfile_size, 0);
		if (r < 0) {
			kc->error = r;
			return r;
		}
	}

	*r_passphrase = kc->i_passphrase;
	*r_passphrase_size = kc->i_passphrase_size;

	return 0;
}

static int get_luks2_key_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	int segment,
	struct volume_key **r_vk)
{
	int r;
	const char *passphrase;
	size_t passphrase_size;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);
	assert(r_vk);

	r = get_passphrase_by_keyfile(cd, kc, &passphrase, &passphrase_size);
	if (r)
		return r;

	r = LUKS2_keyslot_open(cd, keyslot, segment, passphrase, passphrase_size, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_luks2_volume_key_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	return get_luks2_key_by_keyfile(cd, kc, keyslot, CRYPT_DEFAULT_SEGMENT, r_vk);
}

static int get_luks1_volume_key_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	int r;
	const char *passphrase;
	size_t passphrase_size;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);
	assert(r_vk);

	r = get_passphrase_by_keyfile(cd, kc, &passphrase, &passphrase_size);
	if (r)
		return r;

	r = LUKS_open_key_with_hdr(keyslot, passphrase, passphrase_size,
				   crypt_get_hdr(cd, CRYPT_LUKS1), r_vk, cd);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_bitlk_volume_key_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct bitlk_metadata *params,
	struct volume_key **r_vk)
{
	int r;
	const char *passphrase;
	size_t passphrase_size;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);
	assert(params);
	assert(r_vk);

	r = get_passphrase_by_keyfile(cd, kc, &passphrase, &passphrase_size);
	if (r < 0)
		return r;

	r = BITLK_get_volume_key(cd, passphrase, passphrase_size, params, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_fvault2_volume_key_by_keyfile(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct fvault2_params *params,
	struct volume_key **r_vk)
{
	int r;
	const char *passphrase;
	size_t passphrase_size;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);
	assert(params);
	assert(r_vk);

	r = get_passphrase_by_keyfile(cd, kc, &passphrase, &passphrase_size);
	if (r < 0)
		return r;

	r = FVAULT2_get_volume_key(cd, passphrase, passphrase_size, params, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_key_by_key(struct crypt_device *cd __attribute__((unused)),
	struct crypt_keyslot_context *kc,
	int keyslot __attribute__((unused)),
	int segment __attribute__((unused)),
	struct volume_key **r_vk)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_KEY);
	assert(r_vk);

	if (!kc->u.k.volume_key) {
		kc->error = -ENOENT;
		return kc->error;
	}

	*r_vk = crypt_alloc_volume_key(kc->u.k.volume_key_size, kc->u.k.volume_key);
	if (!*r_vk) {
		kc->error = -ENOMEM;
		return kc->error;
	}

	return 0;
}

static int get_volume_key_by_key(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot __attribute__((unused)),
	struct volume_key **r_vk)
{
	return get_key_by_key(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
}

static int get_generic_volume_key_by_key(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	struct volume_key **r_vk)
{
	return get_key_by_key(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
}

static int get_bitlk_volume_key_by_key(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct bitlk_metadata *params __attribute__((unused)),
	struct volume_key **r_vk)
{
	return get_key_by_key(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
}

static int get_fvault2_volume_key_by_key(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const struct fvault2_params *params __attribute__((unused)),
	struct volume_key **r_vk)
{
	return get_key_by_key(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
}

static int get_generic_signed_key_by_key(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	struct volume_key **r_vk,
	struct volume_key **r_signature)
{
	struct volume_key *vk, *vk_sig;

	assert(kc && ((kc->type == CRYPT_KC_TYPE_KEY) ||
		      (kc->type == CRYPT_KC_TYPE_SIGNED_KEY)));
	assert(r_vk);
	assert(r_signature);

	/* return key with no signature */
	if (kc->type == CRYPT_KC_TYPE_KEY) {
		*r_signature = NULL;
		return get_key_by_key(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
	}

	if (!kc->u.ks.volume_key || !kc->u.ks.signature) {
		kc->error = -EINVAL;
		return kc->error;
	}

	vk = crypt_alloc_volume_key(kc->u.ks.volume_key_size, kc->u.ks.volume_key);
	if (!vk) {
		kc->error = -ENOMEM;
		return kc->error;
	}

	vk_sig = crypt_alloc_volume_key(kc->u.ks.signature_size, kc->u.ks.signature);
	if (!vk_sig) {
		crypt_free_volume_key(vk);
		kc->error = -ENOMEM;
		return kc->error;
	}

	*r_vk = vk;
	*r_signature = vk_sig;

	return 0;
}

static int get_luks2_key_by_token(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	int segment,
	struct volume_key **r_vk)
{
	int r;
	struct luks2_hdr *hdr;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_TOKEN);
	assert(r_vk);

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	if (!hdr)
		return -EINVAL;

	r = LUKS2_token_unlock_key(cd, hdr, keyslot, kc->u.t.id, kc->u.t.type,
				   kc->u.t.pin, kc->u.t.pin_size, segment, kc->u.t.usrptr, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_luks2_volume_key_by_token(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	return get_luks2_key_by_token(cd, kc, keyslot, CRYPT_DEFAULT_SEGMENT, r_vk);
}

static int get_passphrase_by_token(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const char **r_passphrase,
	size_t *r_passphrase_size)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_TOKEN);
	assert(r_passphrase);
	assert(r_passphrase_size);

	if (!kc->i_passphrase) {
		r = LUKS2_token_unlock_passphrase(cd, crypt_get_hdr(cd, CRYPT_LUKS2), kc->u.t.id,
				kc->u.t.type, kc->u.t.pin, kc->u.t.pin_size,
				kc->u.t.usrptr, &kc->i_passphrase, &kc->i_passphrase_size);
		if (r < 0) {
			kc->error = r;
			return r;
		}
		kc->u.t.id = r;
	}

	*r_passphrase = kc->i_passphrase;
	*r_passphrase_size = kc->i_passphrase_size;

	return kc->u.t.id;
}

static int get_passphrase_by_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	const char **r_passphrase,
	size_t *r_passphrase_size)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYRING);
	assert(r_passphrase);
	assert(r_passphrase_size);

	if (!kc->i_passphrase) {
		r = crypt_keyring_get_user_key(cd, kc->u.kr.key_description,
					       &kc->i_passphrase, &kc->i_passphrase_size);
		if (r < 0) {
			log_err(cd, _("Failed to read passphrase from keyring."));
			kc->error = -EINVAL;
			return -EINVAL;
		}
	}

	*r_passphrase = kc->i_passphrase;
	*r_passphrase_size = kc->i_passphrase_size;

	return 0;
}

static int get_luks2_key_by_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	int segment,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYRING);
	assert(r_vk);

	r = get_passphrase_by_keyring(cd, kc, CONST_CAST(const char **) &kc->i_passphrase,
		&kc->i_passphrase_size);
	if (r < 0) {
		log_err(cd, _("Failed to read passphrase from keyring."));
		kc->error = -EINVAL;
		return -EINVAL;
	}

	r = LUKS2_keyslot_open(cd, keyslot, segment, kc->i_passphrase, kc->i_passphrase_size, r_vk);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_luks2_volume_key_by_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	return get_luks2_key_by_keyring(cd, kc, keyslot, CRYPT_DEFAULT_SEGMENT, r_vk);
}

static int get_luks1_volume_key_by_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot,
	struct volume_key **r_vk)
{
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYRING);
	assert(r_vk);

	r = get_passphrase_by_keyring(cd, kc, CONST_CAST(const char **) &kc->i_passphrase,
		&kc->i_passphrase_size);
	if (r < 0) {
		log_err(cd, _("Failed to read passphrase from keyring."));
		kc->error = -EINVAL;
		return -EINVAL;
	}

	r = LUKS_open_key_with_hdr(keyslot, kc->i_passphrase, kc->i_passphrase_size,
				   crypt_get_hdr(cd, CRYPT_LUKS1), r_vk, cd);
	if (r < 0)
		kc->error = r;

	return r;
}

static int get_key_by_vk_in_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot __attribute__((unused)),
	int segment __attribute__((unused)),
	struct volume_key **r_vk)
{
	char *key;
	size_t key_size;
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_VK_KEYRING);
	assert(r_vk);

	r = crypt_keyring_get_key_by_name(cd, kc->u.vk_kr.key_description,
					  &key, &key_size);
	if (r < 0) {
		log_err(cd, _("Failed to read volume key candidate from keyring."));
		kc->error = -EINVAL;
		return -EINVAL;
	}

	*r_vk = crypt_alloc_volume_key_by_safe_alloc((void **)&key);
	if (!*r_vk) {
		crypt_safe_free(key);
		kc->error = -ENOMEM;
		return kc->error;
	}

	return 0;
}

static int get_volume_key_by_vk_in_keyring(struct crypt_device *cd,
	struct crypt_keyslot_context *kc,
	int keyslot __attribute__((unused)),
	struct volume_key **r_vk)
{
	return get_key_by_vk_in_keyring(cd, kc, -2 /* unused */, -2 /* unused */, r_vk);
}

static void crypt_keyslot_context_init_common(struct crypt_keyslot_context *kc)
{
	assert(kc);

	kc->version = KC_VERSION_BASIC;
	kc->error = 0;
	kc->i_passphrase = NULL;
	kc->i_passphrase_size = 0;
}

static void keyring_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYRING);

	free(kc->u.kr.i_key_description);
}

static int keyring_get_key_size(struct crypt_device *cd, struct crypt_keyslot_context *kc, size_t *r_key_size)
{
	int r;

	assert(kc && kc->type == CRYPT_KC_TYPE_VK_KEYRING);
	assert(r_key_size);

	if (!kc->u.vk_kr.i_key_size) {
		r = crypt_keyring_get_keysize_by_name(cd, kc->u.vk_kr.key_description, &kc->u.vk_kr.i_key_size);
		if (r < 0)
			return r;
	}

	*r_key_size = kc->u.vk_kr.i_key_size;
	return 0;
}

void crypt_keyslot_context_init_by_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEYRING;
	kc->u.kr.key_description = key_description;

	kc->get_luks2_key = get_luks2_key_by_keyring;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_keyring;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_keyring;
	kc->get_passphrase = get_passphrase_by_keyring;
	kc->context_free = keyring_context_free;
	crypt_keyslot_context_init_common(kc);
}

static void key_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_KEY);

	crypt_free_volume_key(kc->u.k.i_vk);
}

static int key_get_key_size(struct crypt_device *cd __attribute__((unused)),
			       struct crypt_keyslot_context *kc,
			       size_t *r_key_size)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_KEY);
	assert(r_key_size);

	*r_key_size = kc->u.k.volume_key_size;
	return 0;
}

void crypt_keyslot_context_init_by_key_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEY;
	kc->u.k.volume_key = volume_key;
	kc->u.k.volume_key_size = volume_key_size;

	kc->get_luks2_key = get_key_by_key;
	kc->get_luks1_volume_key = get_volume_key_by_key;
	kc->get_luks2_volume_key = get_volume_key_by_key;
	kc->get_plain_volume_key = get_generic_volume_key_by_key;
	kc->get_bitlk_volume_key = get_bitlk_volume_key_by_key;
	kc->get_fvault2_volume_key = get_fvault2_volume_key_by_key;
	kc->get_verity_volume_key = get_generic_signed_key_by_key;
	kc->get_integrity_volume_key = get_generic_volume_key_by_key;
	kc->get_key_size = key_get_key_size;
	kc->context_free = key_context_free;
	crypt_keyslot_context_init_common(kc);
}

static void signed_key_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_SIGNED_KEY);

	crypt_free_volume_key(kc->u.ks.i_vk);
	crypt_free_volume_key(kc->u.ks.i_vk_sig);
}

void crypt_keyslot_context_init_by_signed_key_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_SIGNED_KEY;
	kc->u.ks.volume_key = volume_key;
	kc->u.ks.volume_key_size = volume_key_size;
	kc->u.ks.signature = signature;
	kc->u.ks.signature_size = signature_size;

	kc->get_verity_volume_key = get_generic_signed_key_by_key;
	kc->context_free = signed_key_context_free;
	crypt_keyslot_context_init_common(kc);
}

void crypt_keyslot_context_init_by_passphrase_internal(struct crypt_keyslot_context *kc,
	const char *passphrase,
	size_t passphrase_size)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_PASSPHRASE;
	kc->u.p.passphrase = passphrase;
	kc->u.p.passphrase_size = passphrase_size;

	kc->get_luks2_key = get_luks2_key_by_passphrase;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_passphrase;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_passphrase;
	kc->get_bitlk_volume_key = get_bitlk_volume_key_by_passphrase;
	kc->get_fvault2_volume_key = get_fvault2_volume_key_by_passphrase;
	kc->get_passphrase = get_passphrase_by_passphrase;
	crypt_keyslot_context_init_common(kc);
}

static void keyfile_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_KEYFILE);

	free(kc->u.kf.i_keyfile);
}

void crypt_keyslot_context_init_by_keyfile_internal(struct crypt_keyslot_context *kc,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEYFILE;
	kc->u.kf.keyfile = keyfile;
	kc->u.kf.keyfile_offset = keyfile_offset;
	kc->u.kf.keyfile_size = keyfile_size;

	kc->get_luks2_key = get_luks2_key_by_keyfile;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_keyfile;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_keyfile;
	kc->get_bitlk_volume_key = get_bitlk_volume_key_by_keyfile;
	kc->get_fvault2_volume_key = get_fvault2_volume_key_by_keyfile;
	kc->get_passphrase = get_passphrase_by_keyfile;
	kc->context_free = keyfile_context_free;
	crypt_keyslot_context_init_common(kc);
}

static void token_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_TOKEN);

	free(kc->u.t.i_type);
	crypt_safe_free(kc->u.t.i_pin);
}

void crypt_keyslot_context_init_by_token_internal(struct crypt_keyslot_context *kc,
	int token,
	const char *type,
	const char *pin,
	size_t pin_size,
	void *usrptr)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_TOKEN;
	kc->u.t.id = token;
	kc->u.t.type = type;
	kc->u.t.pin = pin;
	kc->u.t.pin_size = pin_size;
	kc->u.t.usrptr = usrptr;

	kc->get_luks2_key = get_luks2_key_by_token;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_token;
	kc->get_passphrase = get_passphrase_by_token;
	kc->context_free = token_context_free;
	crypt_keyslot_context_init_common(kc);
}

static void vk_in_keyring_context_free(struct crypt_keyslot_context *kc)
{
	assert(kc && kc->type == CRYPT_KC_TYPE_VK_KEYRING);

	free(kc->u.vk_kr.i_key_description);
}

void crypt_keyslot_context_destroy_internal(struct crypt_keyslot_context *kc)
{
	if (!kc)
		return;

	if (kc->context_free)
		kc->context_free(kc);

	crypt_safe_free(kc->i_passphrase);
}

void crypt_keyslot_context_free(struct crypt_keyslot_context *kc)
{
	crypt_keyslot_context_destroy_internal(kc);
	free(kc);
}

static int _crypt_keyslot_context_init_by_passphrase(const char *passphrase,
	size_t passphrase_size,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	struct crypt_keyslot_context *tmp;
	char *i_passphrase = NULL;

	if (!kc || !passphrase)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained) {
		if (passphrase_size) {
			i_passphrase = crypt_safe_alloc(passphrase_size);
			if (!i_passphrase) {
				free(tmp);
				return -ENOMEM;
			}
			crypt_safe_memcpy(i_passphrase, passphrase, passphrase_size);
			passphrase = i_passphrase;
		} else
			/*
			 * some crypto backend libraries expect a pointer even though
			 * passed passphrase size is set to zero.
			 */
			passphrase = "";
	}

	crypt_keyslot_context_init_by_passphrase_internal(tmp, passphrase, passphrase_size);

	if (self_contained) {
		tmp->i_passphrase = i_passphrase;
		tmp->i_passphrase_size = passphrase_size;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_passphrase, 2, 8,
	/* crypt_keyslot_context_init_by_passphrase parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *passphrase,
	size_t passphrase_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_passphrase(passphrase, passphrase_size, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_passphrase, 2, 6,
	/* crypt_keyslot_context_init_by_passphrase parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *passphrase,
	size_t passphrase_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_passphrase(passphrase, passphrase_size, kc, false);
}

static int _crypt_keyslot_context_init_by_keyfile(const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	char *i_keyfile;
	struct crypt_keyslot_context *tmp;

	if (!kc || !keyfile)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained) {
		i_keyfile = strdup(keyfile);
		if (!i_keyfile) {
			free(tmp);
			return -ENOMEM;
		}
		keyfile = i_keyfile;
	}

	crypt_keyslot_context_init_by_keyfile_internal(tmp, keyfile, keyfile_size, keyfile_offset);

	if (self_contained) {
		tmp->u.kf.i_keyfile = i_keyfile;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_keyfile, 2, 8,
	/* crypt_keyslot_context_init_by_keyfile parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_keyfile(keyfile, keyfile_size, keyfile_offset, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_keyfile, 2, 6,
	/* crypt_keyslot_context_init_by_keyfile parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_keyfile(keyfile, keyfile_size, keyfile_offset, kc, false);
}

static int _crypt_keyslot_context_init_by_token(int token,
	const char *type,
	const char *pin, size_t pin_size,
	void *usrptr,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	char *i_type = NULL, *i_pin = NULL;
	struct crypt_keyslot_context *tmp;

	if (!kc || (token < 0 && token != CRYPT_ANY_TOKEN) ||
	    (pin && !pin_size))
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained && type) {
		if (!(i_type = strdup(type)))
			goto err;
		type = i_type;
	}

	if (self_contained && pin) {
		if (!(i_pin = crypt_safe_alloc(pin_size)))
			goto err;
		crypt_safe_memcpy(i_pin, pin, pin_size);
		pin = i_pin;
	}

	crypt_keyslot_context_init_by_token_internal(tmp, token, type, pin, pin_size, usrptr);

	if (self_contained) {
		tmp->u.t.i_pin = i_pin;
		tmp->u.t.i_type = i_type;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
err:
	crypt_safe_free(i_pin);
	free(i_type);
	free(tmp);

	return -ENOMEM;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_token, 2, 8,
	/* crypt_keyslot_context_init_by_token parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	int token,
	const char *type,
	const char *pin, size_t pin_size,
	void *usrptr,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_token(token, type, pin, pin_size, usrptr, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_token, 2, 6,
	/* crypt_keyslot_context_init_by_token parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	int token,
	const char *type,
	const char *pin, size_t pin_size,
	void *usrptr,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_token(token, type, pin, pin_size, usrptr, kc, false);
}

static int _crypt_keyslot_context_init_by_volume_key(const char *volume_key,
	size_t volume_key_size,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	struct volume_key *i_vk = NULL;
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained && volume_key) {
		if (!(i_vk = crypt_alloc_volume_key(volume_key_size, volume_key))) {
			free(tmp);
			return -ENOMEM;
		}
		volume_key = crypt_volume_key_get_key(i_vk);
	}

	crypt_keyslot_context_init_by_key_internal(tmp, volume_key, volume_key_size);

	if (self_contained) {
		tmp->u.k.i_vk = i_vk;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_volume_key, 2, 8,
	/* crypt_keyslot_context_init_by_volume_key parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_volume_key(volume_key, volume_key_size, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_volume_key, 2, 6,
	/* crypt_keyslot_context_init_by_volume_key parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_volume_key(volume_key, volume_key_size, kc, false);
}

static int _crypt_keyslot_context_init_by_signed_key(const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	struct volume_key *i_vk = NULL, *i_vk_sig = NULL;
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained && volume_key) {
		if (!(i_vk = crypt_alloc_volume_key(volume_key_size, volume_key)))
			goto err;
		volume_key = crypt_volume_key_get_key(i_vk);
	}

	if (self_contained && signature) {
		if (!(i_vk_sig = crypt_alloc_volume_key(signature_size, signature)))
			goto err;
		signature = crypt_volume_key_get_key(i_vk_sig);
	}

	crypt_keyslot_context_init_by_signed_key_internal(tmp, volume_key, volume_key_size,
		signature, signature_size);

	if (self_contained) {
		tmp->u.ks.i_vk = i_vk;
		tmp->u.ks.i_vk_sig = i_vk_sig;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
err:
	crypt_free_volume_key(i_vk);
	crypt_free_volume_key(i_vk_sig);
	free(tmp);

	return -ENOMEM;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_signed_key, 2, 8,
	/* crypt_keyslot_context_init_by_signed_key parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_signed_key(volume_key, volume_key_size, signature, signature_size,  kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_signed_key, 2, 7,
	/* crypt_keyslot_context_init_by_signed_key parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_signed_key(volume_key, volume_key_size, signature, signature_size,  kc, false);
}

static int _crypt_keyslot_context_init_by_keyring(const char *key_description,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	char *i_key_description;
	struct crypt_keyslot_context *tmp;

	if (!kc || !key_description)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained) {
		if (!(i_key_description = strdup(key_description))) {
			free(tmp);
			return -ENOMEM;
		}
		key_description = i_key_description;
	}

	crypt_keyslot_context_init_by_keyring_internal(tmp, key_description);

	if (self_contained) {
		tmp->u.kr.i_key_description = i_key_description;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_keyring, 2, 8,
	/* crypt_keyslot_context_init_by_keyring parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_keyring(key_description, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_keyring, 2, 7,
	/* crypt_keyslot_context_init_by_keyring parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_keyring(key_description, kc, false);
}

static int _crypt_keyslot_context_init_by_vk_in_keyring(const char *key_description,
	struct crypt_keyslot_context **kc,
	bool self_contained)
{
	char *i_key_description;
	struct crypt_keyslot_context *tmp;

	if (!kc || !key_description)
		return -EINVAL;

	tmp = crypt_zalloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	if (self_contained) {
		if (!(i_key_description = strdup(key_description))) {
			free(tmp);
			return -ENOMEM;
		}
		key_description = i_key_description;
	}

	tmp->type = CRYPT_KC_TYPE_VK_KEYRING;
	tmp->u.vk_kr.key_description = key_description;

	tmp->get_luks2_key = get_key_by_vk_in_keyring;
	tmp->get_luks2_volume_key = get_volume_key_by_vk_in_keyring;
	tmp->get_key_size = keyring_get_key_size;
	tmp->context_free = vk_in_keyring_context_free;
	crypt_keyslot_context_init_common(tmp);

	if (self_contained) {
		tmp->u.vk_kr.i_key_description = i_key_description;
		tmp->version = KC_VERSION_SELF_CONTAINED;
	}

	*kc = tmp;

	return 0;
}

CRYPT_SYMBOL_EXPORT_NEW(int, crypt_keyslot_context_init_by_vk_in_keyring, 2, 8,
	/* crypt_keyslot_context_init_by_vk_in_keyring parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_vk_in_keyring(key_description, kc, true);
}

CRYPT_SYMBOL_EXPORT_OLD(int, crypt_keyslot_context_init_by_vk_in_keyring, 2, 7,
	/* crypt_keyslot_context_init_by_vk_in_keyring parameters follows */
	struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	return _crypt_keyslot_context_init_by_vk_in_keyring(key_description, kc, false);
}

int crypt_keyslot_context_get_error(struct crypt_keyslot_context *kc)
{
	return kc ? kc->error : -EINVAL;
}

int crypt_keyslot_context_set_pin(struct crypt_device *cd __attribute__((unused)),
	const char *pin, size_t pin_size,
	struct crypt_keyslot_context *kc)
{
	char *i_pin = NULL;

	if (!kc || kc->type != CRYPT_KC_TYPE_TOKEN)
		return -EINVAL;

	if (kc->version >= KC_VERSION_SELF_CONTAINED && pin) {
		if (!(i_pin = crypt_safe_alloc(pin_size)))
			return -ENOMEM;
		crypt_safe_memcpy(i_pin, pin, pin_size);
	}

	crypt_safe_free(kc->u.t.i_pin);
	kc->u.t.i_pin = i_pin;

	kc->u.t.pin = i_pin ?: pin;
	kc->u.t.pin_size = pin_size;
	kc->error = 0;

	return 0;
}

int crypt_keyslot_context_get_type(const struct crypt_keyslot_context *kc)
{
	return kc ? kc->type : -EINVAL;
}

const char *keyslot_context_type_string(const struct crypt_keyslot_context *kc)
{
	assert(kc);

	switch (kc->type) {
	case CRYPT_KC_TYPE_PASSPHRASE:
		return "passphrase";
	case CRYPT_KC_TYPE_KEYFILE:
		return "keyfile";
	case CRYPT_KC_TYPE_TOKEN:
		return "token";
	case CRYPT_KC_TYPE_KEY:
		return "key";
	case CRYPT_KC_TYPE_KEYRING:
		return "keyring";
	case CRYPT_KC_TYPE_VK_KEYRING:
		return "volume key in keyring";
	case CRYPT_KC_TYPE_SIGNED_KEY:
		return "signed key";
	default:
		return "<unknown>";
	}
}
