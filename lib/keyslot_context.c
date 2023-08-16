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

#include <errno.h>

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
		r = keyring_get_passphrase(kc->u.kr.key_description, &kc->i_passphrase, &kc->i_passphrase_size);
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

	return 0;
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
	assert(kc && kc->type == CRYPT_KC_TYPE_PASSPHRASE);
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
	int r;

	assert(cd);
	assert(kc && kc->type == CRYPT_KC_TYPE_VK_KEYRING);
	assert(r_vk);

	r = keyring_read_by_id(kc->u.vk_kr.key_description, &kc->i_volume_key, &kc->i_volume_key_size);
	if (r < 0) {
		log_err(cd, _("Failed to read volume key from keyring."));
		kc->error = -EINVAL;
		return -EINVAL;
	}

	*r_vk = crypt_alloc_volume_key(kc->i_volume_key_size, kc->i_volume_key);
	if (!*r_vk) {
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

static void unlock_method_init_internal(struct crypt_keyslot_context *kc)
{
	assert(kc);

	kc->error = 0;
	kc->i_passphrase = NULL;
	kc->i_passphrase_size = 0;
	kc->i_volume_key = NULL;
	kc->i_volume_key_size = 0;
}

void crypt_keyslot_unlock_by_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEYRING;
	kc->u.kr.key_description = key_description;

	kc->get_luks2_key = get_luks2_key_by_keyring;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_keyring;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_keyring;
	kc->get_passphrase = get_passphrase_by_keyring;
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = NULL;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_key_init_internal(struct crypt_keyslot_context *kc,
	const char *volume_key,
	size_t volume_key_size)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEY;
	kc->u.k.volume_key = volume_key;
	kc->u.k.volume_key_size = volume_key_size;
	kc->get_luks2_key = get_key_by_key;
	kc->get_luks2_volume_key = get_volume_key_by_key;
	kc->get_luks1_volume_key = get_volume_key_by_key;
	kc->get_passphrase = NULL; /* keyslot key context does not provide passphrase */
	kc->get_plain_volume_key = get_generic_volume_key_by_key;
	kc->get_bitlk_volume_key = get_generic_volume_key_by_key;
	kc->get_fvault2_volume_key = get_generic_volume_key_by_key;
	kc->get_verity_volume_key = get_generic_signed_key_by_key;
	kc->get_integrity_volume_key = get_generic_volume_key_by_key;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_signed_key_init_internal(struct crypt_keyslot_context *kc,
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
	kc->get_luks2_key = NULL;
	kc->get_luks2_volume_key = NULL;
	kc->get_luks1_volume_key = NULL;
	kc->get_passphrase = NULL;
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = get_generic_signed_key_by_key;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_passphrase_init_internal(struct crypt_keyslot_context *kc,
	const char *passphrase,
	size_t passphrase_size)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_PASSPHRASE;
	kc->u.p.passphrase = passphrase;
	kc->u.p.passphrase_size = passphrase_size;
	kc->get_luks2_key = get_luks2_key_by_passphrase;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_passphrase;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_passphrase;
	kc->get_passphrase = get_passphrase_by_passphrase;
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = NULL;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_keyfile_init_internal(struct crypt_keyslot_context *kc,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_KEYFILE;
	kc->u.kf.keyfile = keyfile;
	kc->u.kf.keyfile_size = keyfile_size;
	kc->u.kf.keyfile_offset = keyfile_offset;
	kc->get_luks2_key = get_luks2_key_by_keyfile;
	kc->get_luks2_volume_key = get_luks2_volume_key_by_keyfile;
	kc->get_luks1_volume_key = get_luks1_volume_key_by_keyfile;
	kc->get_passphrase = get_passphrase_by_keyfile;
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = NULL;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_token_init_internal(struct crypt_keyslot_context *kc,
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
	kc->get_luks1_volume_key = NULL; /* LUKS1 is not supported */
	kc->get_passphrase = get_passphrase_by_token;
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = NULL;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}

void crypt_keyslot_unlock_by_vk_in_keyring_internal(struct crypt_keyslot_context *kc,
	const char *key_description)
{
	assert(kc);

	kc->type = CRYPT_KC_TYPE_VK_KEYRING;
	kc->u.vk_kr.key_description = key_description;

	kc->get_luks2_key = get_key_by_vk_in_keyring;
	kc->get_luks2_volume_key = get_volume_key_by_vk_in_keyring;
	kc->get_luks1_volume_key = NULL;
	kc->get_passphrase = NULL; /* keyslot key context does not provide passphrase */
	kc->get_plain_volume_key = NULL;
	kc->get_bitlk_volume_key = NULL;
	kc->get_fvault2_volume_key = NULL;
	kc->get_verity_volume_key = NULL;
	kc->get_integrity_volume_key = NULL;
	unlock_method_init_internal(kc);
}


void crypt_keyslot_context_destroy_internal(struct crypt_keyslot_context *kc)
{
	if (!kc)
		return;

	crypt_safe_free(kc->i_passphrase);
	kc->i_passphrase = NULL;
	kc->i_passphrase_size = 0;
	crypt_safe_free(kc->i_volume_key);
	kc->i_volume_key = NULL;
	kc->i_volume_key_size = 0;
}

void crypt_keyslot_context_free(struct crypt_keyslot_context *kc)
{
	crypt_keyslot_context_destroy_internal(kc);
	free(kc);
}

int crypt_keyslot_context_init_by_passphrase(struct crypt_device *cd __attribute__((unused)),
	const char *passphrase,
	size_t passphrase_size,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc || !passphrase)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_passphrase_init_internal(tmp, passphrase, passphrase_size);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_keyfile(struct crypt_device *cd __attribute__((unused)),
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc || !keyfile)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_keyfile_init_internal(tmp, keyfile, keyfile_size, keyfile_offset);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_token(struct crypt_device *cd __attribute__((unused)),
	int token,
	const char *type,
	const char *pin, size_t pin_size,
	void *usrptr,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc || (token < 0 && token != CRYPT_ANY_TOKEN))
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_token_init_internal(tmp, token, type, pin, pin_size, usrptr);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_volume_key(struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_key_init_internal(tmp, volume_key, volume_key_size);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_signed_key(struct crypt_device *cd __attribute__((unused)),
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_signed_key_init_internal(tmp, volume_key, volume_key_size,
		signature, signature_size);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_keyring(struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_keyring_internal(tmp, key_description);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_init_by_vk_in_keyring(struct crypt_device *cd __attribute__((unused)),
	const char *key_description,
	struct crypt_keyslot_context **kc)
{
	struct crypt_keyslot_context *tmp;

	if (!kc)
		return -EINVAL;

	tmp = malloc(sizeof(*tmp));
	if (!tmp)
		return -ENOMEM;

	crypt_keyslot_unlock_by_vk_in_keyring_internal(tmp, key_description);

	*kc = tmp;

	return 0;
}

int crypt_keyslot_context_get_error(struct crypt_keyslot_context *kc)
{
	return kc ? kc->error : -EINVAL;
}

int crypt_keyslot_context_set_pin(struct crypt_device *cd __attribute__((unused)),
	const char *pin, size_t pin_size,
	struct crypt_keyslot_context *kc)
{
	if (!kc || kc->type != CRYPT_KC_TYPE_TOKEN)
		return -EINVAL;

	kc->u.t.pin = pin;
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
