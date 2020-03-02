/*
 * TPM2 utilities for LUKS2 TPM2 type keyslot
 *
 * Copyright (C) 2018-2019 Fraunhofer SIT sponsorred by Infineon Technologies AG
 * Copyright (C) 2019 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019 Daniel Zatovic
 * Copyright (C) 2019 Milan Broz
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

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <json-c/json.h>
#include "utils_tpm2.h"
#include "libcryptsetup.h"

int tpm2_token_get_pcrbanks(const char *pcrbanks_str, uint32_t *pcrbanks)
{
	char *p, *s, *orig_s;
	int r = 0;
	const alg_info *info;

	if (!pcrbanks_str || !pcrbanks)
		return -EINVAL;

	s = strdup(pcrbanks_str);
	if (!s)
		return -ENOMEM;
	orig_s = s;

	while ((p = strsep(&s, ","))) {
		if (!(info = get_alg_info_by_name(p)))
			r = -EINVAL;
		else
			*pcrbanks |= info->crypt_id;
	}

	free(orig_s);
	return r;
}

static void tpm2_token_set_pcrbanks(json_object *jobj, uint32_t pcrbanks)
{
	unsigned i;

	for (i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (pcrbanks & hash_algs[i].crypt_id) {
			json_object_array_add(jobj, json_object_new_string(hash_algs[i].name));
		}
	}
}

int tpm2_token_get_pcrs(const char *pcrs_str, uint32_t *pcrs)
{
	char *p, *s, *orig_s;
	int i, r = 0;

	if (!pcrs_str || !pcrs)
		return -EINVAL;

	s = strdup(pcrs_str);
	if (!s)
		return -ENOMEM;
	orig_s = s;

	while ((p = strsep(&s, ","))) {
		if (sscanf(p, "%i", &i) != 1 || i < 0 || i >= 24) {
			r = -EINVAL;
			break;
		}
		*pcrs |= 1 << i;
	}

	free(orig_s);
	return r;
}

static void tpm2_token_set_pcrs(json_object *jobj, uint32_t pcrselection)
{
	for (int i = 0; i < 32; i++) {
		if (pcrselection & (1 << i))
			json_object_array_add(jobj, json_object_new_int64(i));
	}
}

static bool array_of_type(json_object *jobj, json_type type)
{
	for (int i = 0; i < json_object_array_length(jobj); i++)
		if (!json_object_is_type(json_object_array_get_idx(jobj, i), type))
			return false;
	return true;
}

int tpm2_token_validate(const char *json)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj;
	int r = -EINVAL;

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_token, "nvindex", &jobj) ||
	    !json_object_is_type(jobj, json_type_int))
		goto out;

	if (!json_object_object_get_ex(jobj_token, "nvkey-size", &jobj) ||
	    !json_object_is_type(jobj, json_type_int))
		goto out;

	if (!json_object_object_get_ex(jobj_token, "pcrbanks", &jobj) ||
	    !json_object_is_type(jobj, json_type_array) ||
	    !array_of_type(jobj, json_type_string))
		goto out;

	if (!json_object_object_get_ex(jobj_token, "pcrselection", &jobj) ||
	    !json_object_is_type(jobj, json_type_array) ||
	    !array_of_type(jobj, json_type_int))
		goto out;

	if (!json_object_object_get_ex(jobj_token, "flags", &jobj) ||
	    !json_object_is_type(jobj, json_type_array) ||
	    !array_of_type(jobj, json_type_string))
		goto out;

	r = 0;
out:
	json_object_put(jobj_token);
	return r;
}

int tpm2_token_read(struct crypt_device *cd,
	const char *json,
	uint32_t *tpm_nv,
	uint32_t *tpm_pcr,
	uint32_t *pcrbanks,
	bool *daprotect,
	bool *pin,
	size_t *nvkey_size)
{
	enum json_tokener_error jerr;
	json_object *jobj_token, *jobj, *jobj1;
	const char *str;
	bool tmp_da = false, tmp_pin = false;
	uint32_t tmp_pcrbanks = 0, tmp_pcrselection = 0;
	int i, r = -EINVAL;

	jobj_token = json_tokener_parse_verbose(json, &jerr);
	if (!jobj_token)
		return -EINVAL;

	if (!json_object_object_get_ex(jobj_token, "nvindex", &jobj))
		goto out;
	if (tpm_nv)
		*tpm_nv = (uint32_t)json_object_get_int64(jobj);

	if (!json_object_object_get_ex(jobj_token, "nvkey-size", &jobj))
		goto out;
	if (nvkey_size)
		*nvkey_size = (size_t)json_object_get_int64(jobj);

	/* PCR banks */
	if (!json_object_object_get_ex(jobj_token, "pcrbanks", &jobj))
		goto out;
	for (tmp_pcrbanks = 0, i = 0; i < json_object_array_length(jobj); i++) {
		jobj1 = json_object_array_get_idx(jobj, i);
		tpm2_token_get_pcrbanks(json_object_get_string(jobj1), &tmp_pcrbanks);
	}
	if (pcrbanks)
		*pcrbanks = tmp_pcrbanks;

	/* PCR selection */
	if (!json_object_object_get_ex(jobj_token, "pcrselection", &jobj))
		goto out;
	for (tmp_pcrselection = 0, i = 0; i < json_object_array_length(jobj); i++) {
		jobj1 = json_object_array_get_idx(jobj, i);
		tpm2_token_get_pcrs(json_object_get_string(jobj1), &tmp_pcrselection);
	}
	if (tpm_pcr)
		*tpm_pcr = tmp_pcrselection;

	/* flags */
	if (!json_object_object_get_ex(jobj_token, "flags", &jobj))
		goto out;
	for (i = 0; i < json_object_array_length(jobj); i++) {
		jobj1 = json_object_array_get_idx(jobj, i);
		if (!jobj1 || !(str = json_object_get_string(jobj1)))
			continue;
		else if (!strcmp("DA_PROTECT", str))
			tmp_da = true;
		else if (!strcmp("PIN", str))
			tmp_pin = true;
	}
	if (daprotect)
		*daprotect = tmp_da;
	if (pin)
		*pin = tmp_pin;


	r = 0;
out:
	json_object_put(jobj_token);
	return r;
}

int tpm2_token_add(struct crypt_device *cd,
	uint32_t tpm_nv,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	bool daprotect,
	bool pin,
	size_t nvkey_size)
{
	int token;
	json_object *jobj, *jobj_token;
	const char *string_token;

	jobj_token = json_object_new_object();
	if (!jobj_token)
		return -EINVAL;

	/* type is mandatory field in all tokens and must match handler name member */
	jobj = json_object_new_string("tpm2");
	if (!jobj)
		goto out;
	json_object_object_add(jobj_token, "type", jobj);

	jobj = json_object_new_int64(tpm_nv);
	if (!jobj)
		goto out;
	json_object_object_add(jobj_token, "nvindex", jobj);

	jobj = json_object_new_int64(nvkey_size);
	if (!jobj)
		goto out;
	json_object_object_add(jobj_token, "nvkey-size", jobj);

	/* PCR banks */
	jobj = json_object_new_array();
	tpm2_token_set_pcrbanks(jobj, pcrbanks);
	json_object_object_add(jobj_token, "pcrbanks", jobj);

	/* PCR selection */
	jobj = json_object_new_array();
	tpm2_token_set_pcrs(jobj, tpm_pcr);
	json_object_object_add(jobj_token, "pcrselection", jobj);

	/* flags */
	jobj = json_object_new_array();
	if (daprotect)
		json_object_array_add(jobj, json_object_new_string("DA_PROTECT"));
	if (pin)
		json_object_array_add(jobj, json_object_new_string("PIN"));
	json_object_object_add(jobj_token, "flags", jobj);

	/* keyslots */
	jobj = json_object_new_array();
	if (!jobj)
		goto out;
	json_object_object_add(jobj_token, "keyslots", jobj);

	string_token = json_object_to_json_string_ext(jobj_token, JSON_C_TO_STRING_PLAIN);
	if (!string_token)
		goto out;

	l_dbg(cd, "Token JSON: %s\n", string_token);

	token = crypt_token_json_set(cd, CRYPT_ANY_TOKEN, string_token);
	if (token < 0)
		goto out;

	json_object_put(jobj_token);
	return token;
out:
	l_err(cd, "Error creating token JSON.");
	json_object_put(jobj_token);
	return -EINVAL;
}

static uint32_t token_nvindex(struct crypt_device *cd, int token)
{
	const char *json;
	uint32_t nvindex;

	if (crypt_token_json_get(cd, token, &json) < 0)
		return 0;

	if (tpm2_token_read(cd, json, &nvindex, NULL, NULL, NULL, NULL, NULL))
		return 0;

	return nvindex;
}

int tpm2_token_by_nvindex(struct crypt_device *cd, uint32_t tpm_nv)
{
	crypt_token_info token_info;
	const char *type;
	uint32_t nvindex;
	int i;

	if (!tpm_nv)
		return -EINVAL;

	for (i = 0;; i++) {
		token_info = crypt_token_status(cd, i, &type);

		if (token_info == CRYPT_TOKEN_INVALID)
			break;

		if (token_info != CRYPT_TOKEN_EXTERNAL || strcmp(type, "tpm2"))
			continue;

		nvindex = token_nvindex(cd, i);
		if (!nvindex)
			continue; // FIXME -EINVAL?

		if (nvindex == tpm_nv)
			return i;
	}

	return -ENOENT;
}

int tpm2_token_kill(struct crypt_device *cd, int token)
{
	uint32_t nvindex;
	TSS2_RC r;

	nvindex = token_nvindex(cd, token);
	if (!nvindex)
		return -EINVAL;

	bool exists;

	r = tpm_nv_exists(cd, nvindex, &exists);
	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "Failed to check if TPM2 NV-Index 0x%x exists.", nvindex);
		LOG_TPM_ERR(cd, r);
		return -EINVAL;
	}

	if (exists) {
		r = tpm_nv_undefine(cd, nvindex);
		if (r) {
			l_err(cd, "Failed to undefine TPM2 NV-Index 0x%x.", nvindex);
			return -EINVAL;
		}
	} else {
		l_err(cd, "TPM2 NV-Index 0x%x is already deleted.", nvindex);
	}

	if (crypt_token_json_set(cd, token, NULL) < 0) {
		l_err(cd, "Cannot destroy TPM2 token %d.", token);
		return -EINVAL;
	}

	return 0;
}
