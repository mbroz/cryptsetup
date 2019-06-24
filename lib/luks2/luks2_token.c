/*
 * LUKS - Linux Unified Key Setup v2, token handling
 *
 * Copyright (C) 2016-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2016-2020 Milan Broz
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

#include <assert.h>

#include "luks2_internal.h"

/* Builtin tokens */
extern const crypt_token_handler keyring_handler;

static const crypt_token_handler *token_handlers[LUKS2_TOKENS_MAX] = {
	/* keyring builtin token */
	&keyring_handler,
	NULL
};

static int is_builtin_candidate(const char *type)
{
	return !strncmp(type, LUKS2_BUILTIN_TOKEN_PREFIX, LUKS2_BUILTIN_TOKEN_PREFIX_LEN);
}

int crypt_token_register(const crypt_token_handler *handler)
{
	int i;

	if (is_builtin_candidate(handler->name)) {
		log_dbg(NULL, "'" LUKS2_BUILTIN_TOKEN_PREFIX "' is reserved prefix for builtin tokens.");
		return -EINVAL;
	}

	for (i = 0; i < LUKS2_TOKENS_MAX && token_handlers[i]; i++) {
		if (!strcmp(token_handlers[i]->name, handler->name)) {
			log_dbg(NULL, "Keyslot handler %s is already registered.", handler->name);
			return -EINVAL;
		}
	}

	if (i == LUKS2_TOKENS_MAX)
		return -EINVAL;

	token_handlers[i] = handler;
	return 0;
}

static const crypt_token_handler
*LUKS2_token_handler_type(struct crypt_device *cd, const char *type)
{
	int i;

	for (i = 0; i < LUKS2_TOKENS_MAX && token_handlers[i]; i++)
		if (!strcmp(token_handlers[i]->name, type))
			return token_handlers[i];

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

	if (token < 0 || token >= LUKS2_TOKENS_MAX)
		return -EINVAL;

	if (!json_object_object_get_ex(hdr->jobj, "tokens", &jobj_tokens))
		return -EINVAL;

	snprintf(num, sizeof(num), "%d", token);

	/* Remove token */
	if (!json)
		json_object_object_del(jobj_tokens, num);
	else {

		jobj = json_tokener_parse_verbose(json, &jerr);
		if (!jobj) {
			log_dbg(cd, "Token JSON parse failed.");
			return -EINVAL;
		}

		if (LUKS2_token_validate(cd, hdr->jobj, jobj, num)) {
			json_object_put(jobj);
			return -EINVAL;
		}

		json_object_object_get_ex(jobj, "type", &jobj_type);
		h = LUKS2_token_handler_type(cd, json_object_get_string(jobj_type));

		if (is_builtin_candidate(json_object_get_string(jobj_type)) && !h) {
			log_dbg(cd, "%s is builtin token candidate with missing handler",
				json_object_get_string(jobj_type));
			json_object_put(jobj);
			return -EINVAL;
		}

		if (h && h->validate && h->validate(cd, json)) {
			json_object_put(jobj);
			log_dbg(cd, "Token type %s validation failed.", h->name);
			return -EINVAL;
		}

		json_object_object_add(jobj_tokens, num, jobj);
		if (LUKS2_check_json_size(cd, hdr)) {
			log_dbg(cd, "Not enough space in header json area for new token.");
			json_object_object_del(jobj_tokens, num);
			return -ENOSPC;
		}
	}

	if (commit)
		return LUKS2_hdr_write(cd, hdr) ?: token;

	return token;
}

crypt_token_info LUKS2_token_status(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	const char **type)
{
	const char *tmp;
	const crypt_token_handler *th;
	json_object *jobj_type, *jobj_token;

	if (token < 0 || token >= LUKS2_TOKENS_MAX)
		return CRYPT_TOKEN_INVALID;

	if (!(jobj_token = LUKS2_get_token_jobj(hdr, token)))
		return CRYPT_TOKEN_INACTIVE;

	json_object_object_get_ex(jobj_token, "type", &jobj_type);
	tmp = json_object_get_string(jobj_type);

	if ((th = LUKS2_token_handler_type(cd, tmp))) {
		if (type)
			*type = th->name;
		return is_builtin_candidate(tmp) ? CRYPT_TOKEN_INTERNAL : CRYPT_TOKEN_EXTERNAL;
	}

	if (type)
		*type = tmp;

	return is_builtin_candidate(tmp) ? CRYPT_TOKEN_INTERNAL_UNKNOWN : CRYPT_TOKEN_EXTERNAL_UNKNOWN;
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
			log_dbg(cd, "Token %d (%s) validation failed.", token, h->name);
			return -EINVAL;
		}
	}

	r = h->open(cd, token, buffer, buffer_len, usrptr);
	if (r < 0)
		log_dbg(cd, "Token %d (%s) open failed with %d.", token, h->name, r);

	return r;
}

static void LUKS2_token_buffer_free(struct crypt_device *cd,
		int token,
		void *buffer,
		size_t buffer_len)
{
	const crypt_token_handler *h = LUKS2_token_handler(cd, token);

	if (h->buffer_free)
		h->buffer_free(buffer, buffer_len);
	else {
		crypt_safe_memzero(buffer, buffer_len);
		free(buffer);
	}
}

static int LUKS2_keyslot_open_by_token(struct crypt_device *cd,
	struct luks2_hdr *hdr,
	int token,
	int segment,
	const char *buffer,
	size_t buffer_len,
	struct volume_key **vk)
{
	const crypt_token_handler *h;
	json_object *jobj_token, *jobj_token_keyslots, *jobj;
	unsigned int num = 0;
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
	for (i = 0; i < (int) json_object_array_length(jobj_token_keyslots) && r < 0; i++) {
		jobj = json_object_array_get_idx(jobj_token_keyslots, i);
		num = atoi(json_object_get_string(jobj));
		log_dbg(cd, "Trying to open keyslot %u with token %d (type %s).", num, token, h->name);
		r = LUKS2_keyslot_open(cd, num, segment, buffer, buffer_len, vk);
	}

	if (r < 0)
		return r;

	return num;
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

	r = LUKS2_keyslot_open_by_token(cd, hdr, token,
					(flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) ?
					CRYPT_ANY_SEGMENT : CRYPT_DEFAULT_SEGMENT,
					buffer, buffer_len, &vk);

	LUKS2_token_buffer_free(cd, token, buffer, buffer_len);

	if (r < 0)
		return r;

	keyslot = r;

	if ((name || (flags & CRYPT_ACTIVATE_KEYRING_KEY)) && crypt_use_keyring_for_vk(cd)) {
		if (!(r = LUKS2_volume_key_load_in_keyring_by_keyslot(cd, hdr, vk, keyslot)))
			flags |= CRYPT_ACTIVATE_KEYRING_KEY;
	}

	if (r >= 0 && name)
		r = LUKS2_activate(cd, name, vk, flags);

	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
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

		r = LUKS2_keyslot_open_by_token(cd, hdr, token,
						(flags & CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY) ?
						CRYPT_ANY_SEGMENT : CRYPT_DEFAULT_SEGMENT,
						buffer, buffer_len, &vk);
		LUKS2_token_buffer_free(cd, token, buffer, buffer_len);
		if (r >= 0)
			break;
	}

	keyslot = r;

	if (r >= 0 && (name || (flags & CRYPT_ACTIVATE_KEYRING_KEY)) && crypt_use_keyring_for_vk(cd)) {
		if (!(r = LUKS2_volume_key_load_in_keyring_by_keyslot(cd, hdr, vk, keyslot)))
			flags |= CRYPT_ACTIVATE_KEYRING_KEY;
	}

	if (r >= 0 && name)
		r = LUKS2_activate(cd, name, vk, flags);

	if (r < 0)
		crypt_drop_keyring_key(cd, vk);
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
			h->dump(cd, json_object_to_json_string_ext(jobj_token,
				JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE));
	}
}

int LUKS2_token_json_get(struct crypt_device *cd, struct luks2_hdr *hdr,
			   int token, const char **json)
{
	json_object *jobj_token;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -EINVAL;

	*json = json_object_to_json_string_ext(jobj_token,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	return 0;
}

static int assign_one_keyslot(struct crypt_device *cd, struct luks2_hdr *hdr,
			      int token, int keyslot, int assign)
{
	json_object *jobj1, *jobj_token, *jobj_token_keyslots;
	char num[16];

	log_dbg(cd, "Keyslot %i %s token %i.", keyslot, assign ? "assigned to" : "unassigned from", token);

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
			    int keyslot, int token, int assign)
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
			int keyslot, int token, int assign, int commit)
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
		r = assign_one_token(cd, hdr, keyslot, token, assign);

	if (r < 0)
		return r;

	// FIXME: do not write header in nothing changed
	if (commit)
		return LUKS2_hdr_write(cd, hdr) ?: token;

	return token;
}

int LUKS2_token_is_assigned(struct crypt_device *cd, struct luks2_hdr *hdr,
			    int keyslot, int token)
{
	int i;
	json_object *jobj_token, *jobj_token_keyslots, *jobj;

	if (keyslot < 0 || keyslot >= LUKS2_KEYSLOTS_MAX || token < 0 || token >= LUKS2_TOKENS_MAX)
		return -EINVAL;

	jobj_token = LUKS2_get_token_jobj(hdr, token);
	if (!jobj_token)
		return -ENOENT;

	json_object_object_get_ex(jobj_token, "keyslots", &jobj_token_keyslots);

	for (i = 0; i < (int) json_object_array_length(jobj_token_keyslots); i++) {
		jobj = json_object_array_get_idx(jobj_token_keyslots, i);
		if (keyslot == atoi(json_object_get_string(jobj)))
			return 0;
	}

	return -ENOENT;
}

int LUKS2_tokens_count(struct luks2_hdr *hdr)
{
	json_object *jobj_tokens = LUKS2_get_tokens_jobj(hdr);
	if (!jobj_tokens)
		return -EINVAL;

	return json_object_object_length(jobj_tokens);
}
