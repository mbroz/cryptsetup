/*
 * LUKS - Linux Unified Key Setup v2, token handling
 *
 * Copyright (C) 2016-2017, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2017, Milan Broz. All rights reserved.
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

#include "luks2_internal.h"

/* Internal implementations */
extern const crypt_token_handler keyring_handler;

static const crypt_token_handler *token_handlers[LUKS2_TOKENS_MAX] = {
	&keyring_handler,
	NULL
};

int crypt_token_register(const crypt_token_handler *handler)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX && token_handlers[i]; i++) {
		if (!strcmp(token_handlers[i]->name, handler->name)) {
			log_dbg("Keyslot handler %s is already registered.", handler->name);
			return -EINVAL;
		}
	}

	if (i == LUKS2_KEYSLOTS_MAX) {
		log_dbg("No more space for another token handler.");
		return -EINVAL;
	}

	token_handlers[i] = handler;
	return 0;
}

static const crypt_token_handler
*LUKS2_token_handler_type(struct crypt_device *cd, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_KEYSLOTS_MAX && token_handlers[i]; i++) {
		if (!strcmp(token_handlers[i]->name, type))
			return token_handlers[i];
	}

	return NULL;
}

static const crypt_token_handler
*LUKS2_token_handler(struct crypt_device *cd, int token)
{
	struct luks2_hdr *hdr;
	json_object *jobj1, *jobj2;

	if (token < 0)
		return NULL;

	if (!(hdr = crypt_get_hdr(cd, CRYPT_LUKS2)))
		return NULL;

	if (!(jobj1 = LUKS2_get_token_jobj(hdr, token)))
		return NULL;

	if (!json_object_object_get_ex(jobj1, "type", &jobj2))
		return NULL;

	return LUKS2_token_handler_type(cd, json_object_get_string(jobj2));
}

static int LUKS2_token_find_free(struct luks2_hdr *hdr)
{
	int i;

	for (i = 0; i < LUKS2_TOKENS_MAX; i++)
		if (!LUKS2_get_token_jobj(hdr, i))
			return i;

	return -EINVAL;
}

int LUKS2_token_create(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *json,
	int commit)
{
	const crypt_token_handler *h;
	json_object *jobj_tokens, *jobj_type, *jobj;
	enum json_tokener_error jerr;
	char num[16];

	if (token == CRYPT_ANY_TOKEN) {
		if (!json)
			return -EINVAL;
		token = LUKS2_token_find_free(hdr);
	}

	if (token < 0 || token > LUKS2_TOKENS_MAX)
		return -EINVAL;

	if (!json_object_object_get_ex(hdr->jobj, "tokens", &jobj_tokens))
		return -EINVAL;

	/* Remove token */
	if (!json) {
		snprintf(num, sizeof(num), "%d", token);
		json_object_object_del(jobj_tokens, num);
	} else {

		jobj = json_tokener_parse_verbose(json, &jerr);
		if (!jobj) {
			log_dbg("Token JSON parse failed.");
			return -EINVAL;
		}

		snprintf(num, sizeof(num), "%d", token);

		if (LUKS2_token_validate(hdr->jobj, jobj, num)) {
			json_object_put(jobj);
			return -EINVAL;
		}

		json_object_object_get_ex(jobj, "type", &jobj_type);

		h = LUKS2_token_handler_type(cd, json_object_get_string(jobj_type));
		if (h && h->validate && h->validate(cd, json)) {
			json_object_put(jobj);
			return -EINVAL;
		}

		json_object_object_add(jobj_tokens, num, jobj);
		if (LUKS2_check_json_size(hdr)) {
			log_dbg("New token too large to fit in free metadata space.");
			json_object_object_del(jobj_tokens, num);
			return -ENOSPC;
		}
	}

	if (commit)
		return LUKS2_hdr_write(cd, hdr) ?: token;

	return token;
}

static int LUKS2_token_open(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	const char *json;
	const crypt_token_handler *h;
	int r;

	if (!(h = LUKS2_token_handler(cd, token)))
		return -ENOENT;

	if (h->validate) {
		if (LUKS2_token_json_get(cd, hdr, token, &json))
			return -EINVAL;

		if (h->validate(cd, json)) {
			log_dbg("Token %d (%s) validation failed.", token, h->name);
			return -EINVAL;
		}
	}

	r = h->open(cd, token, buffer, buffer_len, usrptr);
	if (r < 0)
		log_dbg("Token %d (%s) open failed with %d.", token, h->name, r);

	return r;
}

static int LUKS2_keyslot_open_by_token(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char *buffer,
	size_t buffer_len,
	struct volume_key **vk)
{
	const crypt_token_handler *h;
	json_object *jobj_token, *jobj_token_keyslots, *jobj;
	const char *num;
	int i, r;

	if (!(h = LUKS2_token_handler(cd, token)))
		return -ENOENT;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	json_object_object_get_ex(jobj_token, "keyslots", &jobj_token_keyslots);
	if (!jobj_token_keyslots)
		return -EINVAL;

	/* Try to open keyslot referenced in token */
	r = -EINVAL;
	for (i = 0; i < json_object_array_length(jobj_token_keyslots) && r < 0; i++) {
		jobj = json_object_array_get_idx(jobj_token_keyslots, i);
		num = json_object_get_string(jobj);
		log_dbg("Trying to open keyslot %s with token %d (type %s).", num, token, h->name);
		r = LUKS2_keyslot_open(cd, atoi(num), 0, buffer, buffer_len, vk);
	}

	if (r >= 0 && crypt_use_keyring_for_vk(cd))
		r = crypt_volume_key_load_in_keyring(cd, *vk);

	return r < 0 ? r : atoi(num);
}

int LUKS2_token_open_and_activate(struct crypt_device *cd,
		struct luks2_hdr *hdr,
		int token,
		const char *name,
		uint32_t flags,
		void *usrptr)
{
	int keyslot, r;
	char *buffer;
	size_t buffer_len;
	struct volume_key *vk = NULL;

	r = LUKS2_token_open(cd, hdr, token, &buffer, &buffer_len, usrptr);
	if (r < 0)
		return r;

	r = LUKS2_keyslot_open_by_token(cd, hdr, token, buffer, buffer_len, &vk);

	crypt_memzero(buffer, buffer_len);
	free(buffer);

	if (r < 0)
		return r;

	keyslot = r;

	if (name)
		r = LUKS2_activate(cd, name, vk, flags);

	crypt_free_volume_key(vk);

	return r < 0 ? r : keyslot;
}

int LUKS2_token_open_and_activate_any(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	const char *name,
	uint32_t flags)
{
	char *buffer;
	json_object *tokens_jobj;
	size_t buffer_len;
	int keyslot, token, r = -EINVAL;
	struct volume_key *vk = NULL;

	json_object_object_get_ex(hdr->jobj, "tokens", &tokens_jobj);

	json_object_object_foreach(tokens_jobj, slot, val) {
		UNUSED(val);
		token = atoi(slot);

		r = LUKS2_token_open(cd, hdr, token, &buffer, &buffer_len, NULL);
		if (r < 0)
			continue;

		r = LUKS2_keyslot_open_by_token(cd, hdr, token, buffer, buffer_len, &vk);

		crypt_memzero(buffer, buffer_len);
		free(buffer);

		if (r >= 0)
			break;
	}

	keyslot = r;

	if (r >= 0 && name)
		r = LUKS2_activate(cd, name, vk, flags);

	crypt_free_volume_key(vk);

	return r < 0 ? r : keyslot;
}

void LUKS2_token_dump(struct crypt_device *cd, int token)
{
	const crypt_token_handler *h;
	json_object *jobj_token;

	h = LUKS2_token_handler(cd, token);
	if (h && h->dump) {
		jobj_token = LUKS2_get_token_jobj(crypt_get_hdr(cd, CRYPT_LUKS2), token);
		if (jobj_token)
			h->dump(cd, json_object_to_json_string_ext(jobj_token, JSON_C_TO_STRING_PLAIN));
	}
}

int LUKS2_token_json_get(struct crypt_device *cd, struct luks2_hdr *hdr,
			   int token, const char **json)
{
	json_object *jobj_token;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	*json = json_object_to_json_string_ext(jobj_token, JSON_C_TO_STRING_PLAIN);
	return 0;
}

static int assign_one_keyslot(struct crypt_device *cd, struct luks2_hdr *hdr,
			      int token, int keyslot, int assign)
{
	json_object *jobj1, *jobj_token, *jobj_token_keyslots;
	char num[16];

	log_dbg("Token %i %s keyslot %i.", token, assign ? "assigned to" : "unassigned from", keyslot);

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	json_object_object_get_ex(jobj_token, "keyslots", &jobj_token_keyslots);
	if (!jobj_token_keyslots)
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", keyslot);
	if (assign) {
		jobj1 = LUKS2_array_jobj(jobj_token_keyslots, num);
		if (!jobj1)
			json_object_array_add(jobj_token_keyslots, json_object_new_string(num));
	} else {
		jobj1 = LUKS2_array_remove(jobj_token_keyslots, num);
		if (jobj1)
			json_object_object_add(jobj_token, "keyslots", jobj1);
	}

	return 0;
}

static int assign_one_token(struct crypt_device *cd, struct luks2_hdr *hdr,
			    int token, int keyslot, int assign)
{
	json_object *jobj_keyslots;
	int r = 0;

	if (!LUKS2_get_token_jobj(hdr, token))
		return -EINVAL;

	if (keyslot == CRYPT_ANY_SLOT) {
		json_object_object_get_ex(hdr->jobj, "keyslots", &jobj_keyslots);

		json_object_object_foreach(jobj_keyslots, key, val) {
			UNUSED(val);
			r = assign_one_keyslot(cd, hdr, token, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_keyslot(cd, hdr, token, keyslot, assign);

	return r;
}

int LUKS2_token_assign(struct crypt_device *cd, struct luks2_hdr *hdr,
			int token, int keyslot, int assign, int commit)
{
	json_object *jobj_tokens;
	int r = 0;

	if (token == CRYPT_ANY_TOKEN) {
		json_object_object_get_ex(hdr->jobj, "tokens", &jobj_tokens);

		json_object_object_foreach(jobj_tokens, key, val) {
			UNUSED(val);
			r = assign_one_token(cd, hdr, keyslot, atoi(key), assign);
			if (r < 0)
				break;
		}
	} else
		r = assign_one_token(cd, hdr, token, keyslot, assign);

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	if (commit)
		return LUKS2_hdr_write(cd, hdr) ?: token;

	return token;
}
