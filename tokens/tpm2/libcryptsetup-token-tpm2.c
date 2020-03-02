/*
 * LUKS - Linux Unified Key Setup v2, TPM type token handler
 *
 * Copyright (C) 2018-2020 Fraunhofer SIT sponsorred by Infineon Technologies AG
 * Copyright (C) 2019-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2019-2020 Daniel Zatovic
 * Copyright (C) 2019-2020 Milan Broz
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "utils_tpm2.h"
#include "libcryptsetup.h"

static void tpm2_token_dump(struct crypt_device *cd, const char *json)
{
	uint32_t nvindex, pcrs, pcrbanks;
	size_t nvkey_size;
	bool daprotect, pin;
	char buf[1024], num[32];
	unsigned i, n;

	if (tpm2_token_read(cd, json, &nvindex, &pcrs, &pcrbanks,
			    &daprotect, &pin, &nvkey_size)) {
		l_err(cd, "Cannot read JSON token metadata.");
		return;
	}

	l_std(cd, "\tNVindex:  0x%08" PRIx32 "\n", nvindex);
	l_std(cd, "\tNVKey:    %zu [bytes]\n", nvkey_size);

	for (*buf = '\0', n = 0, i = 0; i < 32; i++) {
		if (!(pcrs & (1 << i)))
			continue;
		snprintf(num, sizeof(num), "%s%u", n ? "," : "", i);
		strcat(buf, num);
		n++;
	}
	l_std(cd, "\tPCRs:     %s\n", buf);

	*buf = '\0';
	n = 0;

	for (i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (pcrbanks & hash_algs[i].crypt_id) {
			if (n)
				strcat(buf, ",");
			strcat(buf, hash_algs[i].name);
			n++;
		}
	}

	l_std(cd, "\tPCRBanks: %s\n", buf);

	*buf = '\0';
	n = 0;
	if (daprotect) {
		strcat(buf, "DA_PROTECT");
		n++;
	}
	if (pin)
		strcat(buf, n++ ? ",PIN" : "PIN");
	l_std(cd, "\tflags:    %s\n", buf);
}

static int tpm2_token_open_pin(struct crypt_device *cd,
	int token,
	const char *tpm_pass,
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	int r;
	TSS2_RC tpm_rc;
	uint32_t nvindex, pcrselection, pcrbanks;
	size_t nvkey_size;
	bool daprotect, pin;
	const char *json;

	r = crypt_token_json_get(cd, token, &json);
	if (r < 0) {
		l_err(cd, "Cannot read JSON token metadata.");
		return r;
	}

	r = tpm2_token_read(cd, json, &nvindex, &pcrselection, &pcrbanks,
			    &daprotect, &pin, &nvkey_size);
	if (r < 0) {
		l_err(cd, "Cannot read JSON token metadata.");
		return r;
	}

	if (pin && !tpm_pass) {
		if (daprotect)
			l_std(cd, "TPM stored password has dictionary attack protection turned on. "
				  "Don't enter password too many times.\n");
		return -EAGAIN;
	}

	*buffer = malloc(nvkey_size);
	if (!*buffer)
		 return -ENOMEM;
	*buffer_len = nvkey_size;

	tpm_rc = tpm_nv_read(cd, nvindex, tpm_pass, tpm_pass ? strlen(tpm_pass) : 0,
			   pcrselection, pcrbanks, *buffer, nvkey_size);

	if (tpm_rc == TSS2_RC_SUCCESS)
		return 0;

	if (tpm_rc == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_BAD_AUTH) ||
	    tpm_rc == (TPM2_RC_S | TPM2_RC_1 | TPM2_RC_AUTH_FAIL)) {
		LOG_TPM_ERR(cd, tpm_rc);
		return -EPERM;
	}

	return -EINVAL;
}

static int tpm2_token_open(struct crypt_device *cd,
	int token,
	char **buffer,
	size_t *buffer_len,
	void *usrptr)
{
	return tpm2_token_open_pin(cd, token, NULL, buffer, buffer_len, usrptr);
}

static int _tpm2_token_validate(struct crypt_device *cd, const char *json)
{
	return tpm2_token_validate(json);
}

const crypt_token_handler cryptsetup_token_handler = {
	.name  = "tpm2",
	.open  = tpm2_token_open,
	.open_pin = tpm2_token_open_pin,
	.validate = _tpm2_token_validate,
	.dump = tpm2_token_dump
};
