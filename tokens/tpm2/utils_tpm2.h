/*
 * TPM2 utilities for LUKS2 TPM2 type keyslot
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

#ifndef _UTILS_TPM2_H
#define _UTILS_TPM2_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_rc.h>

#include "libcryptsetup_cli.h"

#define l_std(cd, x...) crypt_cli_logger(cd, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define l_err(cd, x...) crypt_cli_logger(cd, CRYPT_LOG_ERROR,  __FILE__, __LINE__, x)
#define l_dbg(cd, x...) crypt_cli_logger(cd, CRYPT_LOG_DEBUG,  __FILE__, __LINE__, x)

#define LOG_TPM_ERR(cd, r) l_err(cd, "TPM error: %s (code 0x%08x)", Tss2_RC_Decode(r), r)

/* Flags for activating the PCR banks */
#define CRYPT_TPM_PCRBANK_SHA1		((uint32_t) (1 << 0))
#define CRYPT_TPM_PCRBANK_SHA256	((uint32_t) (1 << 1))
#define CRYPT_TPM_PCRBANK_SHA384	((uint32_t) (1 << 2))
#define CRYPT_TPM_PCRBANK_SHA512	((uint32_t) (1 << 3))
#define CRYPT_TPM_PCRBANK_SM3_256	((uint32_t) (1 << 4))
#define CRYPT_TPM_PCRBANK_SHA3_256	((uint32_t) (1 << 5))
#define CRYPT_TPM_PCRBANK_SHA3_384	((uint32_t) (1 << 6))
#define CRYPT_TPM_PCRBANK_SHA3_512	((uint32_t) (1 << 7))

typedef struct alg_info alg_info;
struct alg_info {
    const char *name;
    TPM2_ALG_ID id;
    uint32_t crypt_id;
};

static const alg_info hash_algs[] = {
	{ .name = "sha1",	.id = TPM2_ALG_SHA1,		.crypt_id = CRYPT_TPM_PCRBANK_SHA1 },
	{ .name = "sha256",	.id = TPM2_ALG_SHA256,		.crypt_id = CRYPT_TPM_PCRBANK_SHA256 },
	{ .name = "sha384",	.id = TPM2_ALG_SHA384,		.crypt_id = CRYPT_TPM_PCRBANK_SHA384 },
	{ .name = "sha512",	.id = TPM2_ALG_SHA512,		.crypt_id = CRYPT_TPM_PCRBANK_SHA512 },
	{ .name = "sm3_256",	.id = TPM2_ALG_SM3_256,		.crypt_id = CRYPT_TPM_PCRBANK_SM3_256 },
	{ .name = "sha3_256",	.id = TPM2_ALG_SHA3_256,	.crypt_id = CRYPT_TPM_PCRBANK_SHA3_256 },
	{ .name = "sha3_384",	.id = TPM2_ALG_SHA3_384,	.crypt_id = CRYPT_TPM_PCRBANK_SHA3_384 },
	{ .name = "sha3_512",	.id = TPM2_ALG_SHA3_512,	.crypt_id = CRYPT_TPM_PCRBANK_SHA3_512 }
};

#define CRYPT_HASH_ALGS_COUNT (sizeof(hash_algs)/sizeof(hash_algs[0]))

const alg_info *get_alg_info_by_name(const char *name);
const alg_info *get_alg_info_by_id(TPM2_ALG_ID id);
const alg_info *get_alg_info_by_crypt_id(uint32_t crypt_id);

TSS2_RC tpm_nv_read(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	char *nvkey,
	size_t nvkey_size);


TSS2_RC tpm_nv_write(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	const char *buffer,
	size_t buffer_size);

TSS2_RC tpm_nv_define(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	bool daprotect,
	const char *ownerpw,
	size_t ownerpw_size,
	size_t nvkey_size);

TSS2_RC tpm_init(struct crypt_device *cd, ESYS_CONTEXT **ctx, const char *tcti_conf);

TSS2_RC tpm_nv_undefine(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t tpm_nv);

TSS2_RC tpm_nv_find(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t *tpm_nv);

TSS2_RC tpm_nv_exists(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t tpm_nv, bool *exists);

int tpm_get_random(struct crypt_device *cd, ESYS_CONTEXT *ctx, char *random_bytes, size_t len);

/*
 * TPM2 token helpers
 */

int tpm2_token_add(struct crypt_device *cd,
	int token,
	uint32_t tpm_nv,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	bool daprotect,
	bool pin,
	size_t nvkey_size);

int tpm2_token_read(struct crypt_device *cd,
	const char *json,
	uint32_t *tpm_nv,
	uint32_t *tpm_pcr,
	uint32_t *pcrbanks,
	bool *daprotect,
	bool *pin,
	size_t *nvkey_size);

int tpm2_token_by_nvindex(struct crypt_device *cd, uint32_t tpm_nv);

int tpm2_token_kill(struct crypt_device *cd, ESYS_CONTEXT *ctx, int token);
int tpm2_token_validate(const char *json);

int tpm2_token_get_pcrbanks(const char *pcrbanks_str, uint32_t *pcrbanks);
int tpm2_token_get_pcrs(const char *pcrs_str, uint32_t *pcrs);
TPMS_PCR_SELECTION *tpm2_get_pcrs_by_alg(TPMS_CAPABILITY_DATA *savedPCRs, uint32_t pcrbank);
TSS2_RC getPCRsCapability(struct crypt_device *cd, ESYS_CONTEXT *ctx, TPMS_CAPABILITY_DATA **savedPCRs);
TSS2_RC tpm2_supports_algs_for_pcrs(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t pcrbanks, uint32_t pcrs, bool *supports);

#endif /* _UTILS_TPM2_H */
