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

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include "utils_tpm2.h"
#include "libcryptsetup.h"

const alg_info *get_alg_info_by_name(const char *name) {
	unsigned i;

	for(i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (!strcasecmp(hash_algs[i].name, name))
			return &hash_algs[i];
	}

	return NULL;
}

const alg_info *get_alg_info_by_id(TPM2_ALG_ID id) {
	unsigned i;

	for(i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (hash_algs[i].id == id)
			return &hash_algs[i];
	}

	return NULL;
}

const alg_info *get_alg_info_by_crypt_id(uint32_t crypt_id) {
	unsigned i;

	for(i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (hash_algs[i].crypt_id == crypt_id)
			return &hash_algs[i];
	}

	return NULL;
}

/*
 * Initialize the TPM including a potentially necessary TPM2_Startup command,
 * which is needed for simulators and RPi TPM hats.
 */
TSS2_RC tpm_init(struct crypt_device *cd, ESYS_CONTEXT **ctx, const char *tcti_conf)
{
	TSS2_RC r;
	l_dbg(cd, "Initializing ESYS connection");

	TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
	r = Tss2_TctiLdr_Initialize (tcti_conf, &tcti_ctx);
	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "Error initializing TCTI");
		return r;
	}

	r = Esys_Initialize(ctx, tcti_ctx, NULL);
	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "Error initializing ESYS");
		return r;
	}

	r = Esys_Startup(*ctx, TPM2_SU_CLEAR);
	if (r == TPM2_RC_INITIALIZE) {
		l_dbg(cd, "TPM already started up. Not an error!");
		r = TSS2_RC_SUCCESS;
	}

	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "TPM StartUp command failed");
		Esys_Finalize(ctx);
	}

	return r;
}

static TSS2_RC tpm_getPcrDigest(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	const TPML_PCR_SELECTION *pcrs,
	TPM2_ALG_ID hashAlg,
	TPM2B_DIGEST *pcrDigest)
{
	TSS2_RC r;
	TPM2B_AUTH auth = {0};
	ESYS_TR hash;
	TPML_DIGEST *value;
	TPML_PCR_SELECTION readPCRs = {
		.count = 1,
		.pcrSelections = {}
	};
	TPM2B_DIGEST *returnPcrDigest;
	TPM2B_MAX_BUFFER digest;
	unsigned int i, j;

	r = Esys_HashSequenceStart(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			&auth, hashAlg, &hash);
	if (r)
		return r;

	for (i = 0; i < pcrs->count; i++) {

		readPCRs.pcrSelections[0].hash = pcrs->pcrSelections[i].hash;
		readPCRs.pcrSelections[0].sizeofSelect = 3;
		for (j = 0; j < 24; j++) {
			if (!(pcrs->pcrSelections[i].pcrSelect[j / 8] & (1 << (j % 8))))
				continue;

			readPCRs.pcrSelections[0].pcrSelect[0] = 0;
			readPCRs.pcrSelections[0].pcrSelect[1] = 0;
			readPCRs.pcrSelections[0].pcrSelect[2] = 0;

			readPCRs.pcrSelections[0].pcrSelect[j / 8] = (1 << (j % 8));

			r = Esys_PCR_Read(ctx,
					ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
					&readPCRs, NULL, NULL, &value);
			//TODO:            if (r == 0x984) continue;
			if (r) {
				l_err(cd, "PCR Read failed");
				return r;
			}
			if (!value->count) {
				free(value);
				continue;
			}

			digest.size = value->digests[0].size;
			memcpy(&digest.buffer[0], &value->digests[0].buffer, digest.size);

			r = Esys_SequenceUpdate(ctx, hash, ESYS_TR_PASSWORD, ESYS_TR_NONE,
						ESYS_TR_NONE, &digest);
			free(value);
			if (r)
				return r;
		}
	}

	r = Esys_SequenceComplete(ctx, hash, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
			NULL, TPM2_RH_NULL, &returnPcrDigest, NULL);
	if (r)
		return r;

	*pcrDigest = *returnPcrDigest;
	free(returnPcrDigest);

	return 0;
}

static TSS2_RC tpm_policy_Read(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	ESYS_TR *authSession,
	TPM2B_DIGEST *authPolicy)
{
	TSS2_RC r;
	ESYS_TR session;
	TPM2B_DIGEST *policyDigest;
	TPM2B_DIGEST pcrDigest = {
		.size = 0,
		.buffer = {}
	};
	TPML_PCR_SELECTION pcrs = {
		.count = 0
	};
	TPMT_SYM_DEF sym = {
		.algorithm = TPM2_ALG_AES,
		.keyBits = {
			.aes = 128
		},
		.mode = {
			.aes = TPM2_ALG_CFB
		}
	};
	unsigned int i;

	if (pcrbanks == 0) {
		l_err(cd, "No banks selected.");
		return TSS2_BASE_RC_BAD_SIZE;
	}

	for (i = 0; i < CRYPT_HASH_ALGS_COUNT; i++) {
		if (pcrbanks & hash_algs[i].crypt_id) {
			pcrs.pcrSelections[pcrs.count].hash = hash_algs[i].id;
			pcrs.count++;
		}
	}

	for (i = 0; i < pcrs.count; i++) {
		pcrs.pcrSelections[i].sizeofSelect = 3;
		pcrs.pcrSelections[i].pcrSelect[0] = tpm_pcr      & 0xff;
		pcrs.pcrSelections[i].pcrSelect[1] = tpm_pcr >> 8 & 0xff;
		pcrs.pcrSelections[i].pcrSelect[2] = tpm_pcr >>16 & 0xff;
	}

	r = tpm_getPcrDigest(cd, ctx, &pcrs, TPM2_ALG_SHA256, &pcrDigest);
	if (r != TSS2_RC_SUCCESS)
		return r;

	r = Esys_StartAuthSession(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_POLICY,
				  &sym, TPM2_ALG_SHA256, &session);
	if (r != TSS2_RC_SUCCESS) {
		return r;
	}

	r = Esys_PolicyPCR(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			   &pcrDigest, &pcrs);
	if (r != TSS2_RC_SUCCESS) {
		Esys_FlushContext(ctx, session);
		return r;
	}

	r = Esys_PolicyPassword(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
	if (r != TSS2_RC_SUCCESS) {
		Esys_FlushContext(ctx, session);
		return r;
	}

	r = Esys_PolicyCommandCode(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE,
				   ESYS_TR_NONE, TPM2_CC_NV_Read);
	if (r != TSS2_RC_SUCCESS) {
		Esys_FlushContext(ctx, session);
		return r;
	}

	r = Esys_PolicyGetDigest(ctx, session, ESYS_TR_NONE, ESYS_TR_NONE,
				 ESYS_TR_NONE, &policyDigest);
	if (r != TSS2_RC_SUCCESS) {
		Esys_FlushContext(ctx, session);
		return r;
	}

	if (authSession)
		*authSession = session;
	else
		Esys_FlushContext(ctx, session);

	if (authPolicy)
		*authPolicy = *policyDigest;
	free(policyDigest);

	return TSS2_RC_SUCCESS;
}

static TSS2_RC tpm_nv_prep(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	ESYS_TR *nvIndex)
{
	TSS2_RC r;
	TPM2B_AUTH tpm_pin = {
		.size = pin_size,
		.buffer = {}
	};

	if (pin_size > sizeof(tpm_pin.buffer))
		return TSS2_BASE_RC_BAD_SIZE;

	if (pin_size > 0)
		memcpy(&tpm_pin.buffer[0], pin, tpm_pin.size);

	if (tpm_nv < 0x01800000 || tpm_nv > 0x01BFFFFF) {
		l_err(cd, "NV index handle %08x out of range", tpm_nv);
		return TSS2_BASE_RC_BAD_SIZE;
	}

	r = Esys_TR_FromTPMPublic(ctx, tpm_nv, ESYS_TR_NONE, ESYS_TR_NONE,
				  ESYS_TR_NONE, nvIndex);
	if (r != TSS2_RC_SUCCESS) {
		return r;
	}

	r = Esys_TR_SetAuth(ctx, *nvIndex, &tpm_pin);
	if (r != TSS2_RC_SUCCESS) {
		return r;
	}

	return r;
}

TSS2_RC tpm_nv_read(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	uint32_t tpm_pcr,
	uint32_t pcrbanks,
	char *nvkey,
	size_t nvkey_size)
{
	TSS2_RC r;
	ESYS_TR nvIndex, session;
	TPM2B_MAX_NV_BUFFER *nv_pass = NULL;

	r = tpm_nv_prep(cd, ctx, tpm_nv, pin, pin_size, &nvIndex);
	if (r != TSS2_RC_SUCCESS)
		return r;

	r = tpm_policy_Read(cd, ctx, tpm_pcr, pcrbanks, &session, NULL);
	if (r != TSS2_RC_SUCCESS) {
		goto out;
	}
	Esys_TRSess_SetAttributes(ctx, session, 0, TPMA_SESSION_CONTINUESESSION);

	r = Esys_NV_Read(ctx, nvIndex, nvIndex,	session, ESYS_TR_NONE, ESYS_TR_NONE,
			 nvkey_size, 0, &nv_pass);
	if (r != TSS2_RC_SUCCESS) {
		r = Esys_FlushContext(ctx, session);
		goto out;
	}

	if (nvkey_size != nv_pass->size) {
		l_err(cd, "VK lengths differ");
		r = TSS2_BASE_RC_BAD_VALUE;
		goto out;
	}

	memcpy(nvkey, &nv_pass->buffer[0], nvkey_size);
out:
	free(nv_pass);

	return r;
}

TSS2_RC tpm_nv_write(struct crypt_device *cd,
	ESYS_CONTEXT *ctx,
	uint32_t tpm_nv,
	const char *pin,
	size_t pin_size,
	const char *buffer,
	size_t buffer_size)
{
	TSS2_RC r;
	ESYS_TR nvIndex;
	TPM2B_MAX_NV_BUFFER nv_pass = {
		.size = buffer_size,
		.buffer = {}
	};

	if (buffer_size > sizeof(nv_pass.buffer))
		return TPM2_RC_FAILURE;

	memcpy(&nv_pass.buffer[0], buffer, buffer_size);

	r = tpm_nv_prep(cd, ctx, tpm_nv, pin, pin_size, &nvIndex);
	if (r != TSS2_RC_SUCCESS)
		return r;

	r = Esys_NV_Write(ctx, nvIndex, nvIndex, ESYS_TR_PASSWORD, ESYS_TR_NONE,
			  ESYS_TR_NONE, &nv_pass, 0);

	return r;
}

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
	size_t nvkey_size)
{
	TSS2_RC r;
	ESYS_TR nvIndex;
	TPM2B_AUTH tpm_pin = {
		.size = pin_size,
		.buffer = {}
	};
	TPM2B_NV_PUBLIC nvInfo = {
		.size = 0,
		.nvPublic = {
			.nvIndex = tpm_nv,
			.nameAlg = TPM2_ALG_SHA256,
			.attributes = TPMA_NV_AUTHWRITE | TPMA_NV_POLICYREAD | TPMA_NV_WRITEALL,
			.authPolicy = {
				.size = 0,
				.buffer = {},
			},
			.dataSize = (uint16_t)nvkey_size
		}
	};
	TPM2B_AUTH ownerauth = {
		.size = ownerpw_size,
		.buffer={}
	};

	if (nvkey_size > UINT16_MAX)
		return TPM2_RC_FAILURE;

	if (pin_size > sizeof(tpm_pin.buffer))
		return TPM2_RC_FAILURE;

	if (pin_size > 0)
		memcpy(&tpm_pin.buffer[0], pin, tpm_pin.size);

	if (!daprotect)
		nvInfo.nvPublic.attributes |= TPMA_NV_NO_DA;

	if (tpm_nv < 0x01800000 || tpm_nv > 0x01BFFFFF) {
		l_err(cd, "NV index handle %08x out of range", tpm_nv);
		return TPM2_RC_FAILURE;
	}

	if (ownerpw != NULL) {
		if (ownerpw_size > sizeof(ownerauth.buffer))
			return TPM2_RC_FAILURE;
		memcpy(&ownerauth.buffer[0], ownerpw, ownerauth.size);

		r = Esys_TR_SetAuth(ctx, ESYS_TR_RH_OWNER, &ownerauth);
		if (r != TSS2_RC_SUCCESS)
			return r;
	}

	r = tpm_policy_Read(cd, ctx, tpm_pcr, pcrbanks, NULL, &nvInfo.nvPublic.authPolicy);
	if (r != TSS2_RC_SUCCESS)
		return r;

	l_dbg(cd, "Defining TPM handle 0x%08x.", tpm_nv);

	r = Esys_NV_DefineSpace(ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
				ESYS_TR_NONE, &tpm_pin, &nvInfo, &nvIndex);
	return r;
}

TSS2_RC tpm_nv_undefine(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t tpm_nv)
{
	TSS2_RC r;
	;
	ESYS_TR nvIndex;

	r = tpm_nv_prep(cd, ctx, tpm_nv, NULL, 0, &nvIndex);
	if (r != TSS2_RC_SUCCESS)
		return r;

	l_dbg(cd, "Deleting TPM handle 0x%08x.", tpm_nv);

	r = Esys_NV_UndefineSpace(ctx, ESYS_TR_RH_OWNER, nvIndex, ESYS_TR_PASSWORD,
				  ESYS_TR_NONE, ESYS_TR_NONE);

	return r;
}

TSS2_RC tpm_nv_find(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t *tpm_nv)
{
	TSS2_RC r;
	;
	ESYS_TR nvIndex;
	TPMS_CAPABILITY_DATA *capabilityData;
	int i;

	*tpm_nv = 0;

	r = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, 0x01000000, 0xffff, NULL, &capabilityData);
	if (r != TSS2_RC_SUCCESS)
		return r;

	for (nvIndex = 0x01BF0000; nvIndex < 0x01BF00FF; nvIndex++) {
		for (i = capabilityData->data.handles.count-1; i >= 0; i--) {
			if (nvIndex == capabilityData->data.handles.handle[i])
				break;
		}

		if (i < 0) {
			*tpm_nv = nvIndex;
			l_dbg(cd, "Found NV-Index 0x%08x.", nvIndex);
			free(capabilityData);
			return 0;
		} else
			l_dbg(cd, "NV-Index 0x%08x already in use.", nvIndex);
	}

	free(capabilityData);
	return r;
}

TSS2_RC tpm_nv_exists(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t tpm_nv, bool *exists)
{
	TSS2_RC r;
	TPMS_CAPABILITY_DATA *capabilityData;
	int i;

	r = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
			       TPM2_CAP_HANDLES, 0x01000000, 0xffff, NULL, &capabilityData);
	if (r != TSS2_RC_SUCCESS) {
		l_err(cd, "Error retrieving TPM capabilities.");
		return r;
	}

	*exists = false;
	for (i = capabilityData->data.handles.count-1; i >= 0; i--) {
		if (tpm_nv == capabilityData->data.handles.handle[i]) {
			l_dbg(cd, "TPM-NV-Handle 0x%08x does exist.", tpm_nv);
			*exists = true;
			break;
		}
	}

	free(capabilityData);
	return r;
}

int tpm_get_random(struct crypt_device *cd, ESYS_CONTEXT *ctx, char *random_bytes, size_t len)
{
	TSS2_RC r;
	TPM2B_DIGEST *random_bytes_in;
	unsigned int i = 0;
	unsigned int j;
	unsigned int retries = 5;

	if (len > UINT16_MAX)
		return -EINVAL;

	while (retries && i < len) {
		/* SHA256 should be supported on all TPM2 chips, so 256 bits
		   should be minimal supported random length */
		r = Esys_GetRandom(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
				TPM2_SHA256_DIGEST_SIZE, &random_bytes_in);

		if (r != TPM2_RC_SUCCESS) {
			retries--;
			continue;
		}

		for (j = 0; j < random_bytes_in->size && i < len; j++) {
			random_bytes[i] = random_bytes_in->buffer[j];
			random_bytes_in->buffer[j] = 0;
			i++;
		}

		free(random_bytes_in);
	}

	if (i < len) {
		return -EINVAL;
	}

	return 0;
}

bool pcrs_in_selection(uint32_t required_pcrs, TPMS_PCR_SELECTION *selection) {
	uint32_t selected_pcrs = 0;
	int i = 0;

	if (!selection)
		return false;

	for (i = 0; i < selection->sizeofSelect; i++)
		selected_pcrs |= selection->pcrSelect[i] << (i * 8);

	return (selected_pcrs & required_pcrs) == required_pcrs;
}

TPMS_PCR_SELECTION *tpm2_get_pcrs_by_alg(TPMS_CAPABILITY_DATA *savedPCRs, uint32_t pcrbank)
{
	unsigned i;
	const alg_info *info = get_alg_info_by_crypt_id(pcrbank);

	if (!savedPCRs)
		return NULL;
	if (!info)
		return NULL;

	for (i = 0; i < savedPCRs->data.assignedPCR.count; i++) {
		if (savedPCRs->data.assignedPCR.pcrSelections[i].hash == info->id)
			return &savedPCRs->data.assignedPCR.pcrSelections[i];
	}

	return NULL;
}

TSS2_RC getPCRsCapability(struct crypt_device *cd, ESYS_CONTEXT *ctx, TPMS_CAPABILITY_DATA **savedPCRs)
{
	TSS2_RC r;
	TPMS_CAPABILITY_DATA *currentPCRs;
	TPMI_YES_NO more_data;
	size_t current_count = 0;

	*savedPCRs = NULL;

	do {
		r = Esys_GetCapability(ctx, ESYS_TR_NONE, ESYS_TR_NONE,
				ESYS_TR_NONE, TPM2_CAP_PCRS, 0, TPM2_NUM_PCR_BANKS,
				&more_data, &currentPCRs);
		if (r != TSS2_RC_SUCCESS) {
			if (*savedPCRs)
				free(*savedPCRs);
			goto out;
		}

		if (currentPCRs->data.assignedPCR.count + current_count > TPM2_NUM_PCR_BANKS) {
			currentPCRs->data.assignedPCR.count = TPM2_NUM_PCR_BANKS - current_count;
		}

		if (*savedPCRs) {
			memmove(&(*savedPCRs)->data.assignedPCR.pcrSelections[current_count],
					currentPCRs->data.assignedPCR.pcrSelections,
					currentPCRs->data.assignedPCR.count * sizeof(currentPCRs->data.assignedPCR.pcrSelections[0]));
			free(currentPCRs);
			current_count += currentPCRs->data.assignedPCR.count;
		} else {
			*savedPCRs = currentPCRs;
			current_count = currentPCRs->data.assignedPCR.count;
		}
	} while (more_data && current_count < TPM2_NUM_PCR_BANKS);

out:
	return r;
}

TSS2_RC tpm2_supports_algs_for_pcrs(struct crypt_device *cd, ESYS_CONTEXT *ctx, uint32_t pcrbanks, uint32_t pcrs, bool *supports)
{
	TSS2_RC r = TSS2_RC_SUCCESS;
	TPMS_CAPABILITY_DATA *savedPCRs;
	TPMS_PCR_SELECTION *supported_pcrs_selection;
	unsigned int i = 0;

	r = getPCRsCapability(cd, ctx, &savedPCRs);
	if (r != TSS2_RC_SUCCESS)
		return r;

	for (i = 0; i < sizeof(pcrbanks) * 8; i++) {
		if (pcrbanks & (1 << i)) {
			supported_pcrs_selection = tpm2_get_pcrs_by_alg(savedPCRs, pcrbanks & (1 << i));
			if (!supported_pcrs_selection) {
				*supports = false;
				goto out;
			}
			if (!pcrs_in_selection(pcrs, supported_pcrs_selection)) {
				*supports = false;
				goto out;
			}
		}
	}
	*supports = true;
out:
	free(savedPCRs);
	return r;
}
