/*
 * libcryptsetup - cryptsetup library internal
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2023 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2023 Milan Broz
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

#ifndef INTERNAL_H
#define INTERNAL_H

#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <fcntl.h>
#include <assert.h>

#include "nls.h"
#include "bitops.h"
#include "utils_blkid.h"
#include "utils_crypt.h"
#include "utils_loop.h"
#include "utils_dm.h"
#include "utils_keyring.h"
#include "utils_io.h"
#include "crypto_backend/crypto_backend.h"
#include "utils_storage_wrappers.h"

#include "libcryptsetup.h"

#include "libcryptsetup_macros.h"
#include "libcryptsetup_symver.h"

#define LOG_MAX_LEN		4096
#define MAX_DM_DEPS		32

#define CRYPT_SUBDEV           "SUBDEV" /* prefix for sublayered devices underneath public crypt types */

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

struct crypt_device;
struct luks2_reencrypt;

struct volume_key {
	int id;
	size_t keylength;
	const char *key_description;
	struct volume_key *next;
	char key[];
};

struct volume_key *crypt_alloc_volume_key(size_t keylength, const char *key);
struct volume_key *crypt_generate_volume_key(struct crypt_device *cd, size_t keylength);
void crypt_free_volume_key(struct volume_key *vk);
int crypt_volume_key_set_description(struct volume_key *key, const char *key_description);
void crypt_volume_key_set_id(struct volume_key *vk, int id);
int crypt_volume_key_get_id(const struct volume_key *vk);
void crypt_volume_key_add_next(struct volume_key **vks, struct volume_key *vk);
struct volume_key *crypt_volume_key_next(struct volume_key *vk);
struct volume_key *crypt_volume_key_by_id(struct volume_key *vk, int id);

struct crypt_pbkdf_type *crypt_get_pbkdf(struct crypt_device *cd);
int init_pbkdf_type(struct crypt_device *cd,
		    const struct crypt_pbkdf_type *pbkdf,
		    const char *dev_type);
int verify_pbkdf_params(struct crypt_device *cd,
			const struct crypt_pbkdf_type *pbkdf);
int crypt_benchmark_pbkdf_internal(struct crypt_device *cd,
				   struct crypt_pbkdf_type *pbkdf,
				   size_t volume_key_size);
const char *crypt_get_cipher_spec(struct crypt_device *cd);
uint32_t pbkdf_adjusted_phys_memory_kb(void);

/* Device backend */
struct device;
int device_alloc(struct crypt_device *cd, struct device **device, const char *path);
int device_alloc_no_check(struct device **device, const char *path);
void device_close(struct crypt_device *cd, struct device *device);
void device_free(struct crypt_device *cd, struct device *device);
const char *device_path(const struct device *device);
const char *device_dm_name(const struct device *device);
const char *device_block_path(const struct device *device);
void device_topology_alignment(struct crypt_device *cd,
			       struct device *device,
			       unsigned long *required_alignment, /* bytes */
			       unsigned long *alignment_offset,   /* bytes */
			       unsigned long default_alignment);
size_t device_block_size(struct crypt_device *cd, struct device *device);
int device_read_ahead(struct device *device, uint32_t *read_ahead);
int device_size(struct device *device, uint64_t *size);
int device_open(struct crypt_device *cd, struct device *device, int flags);
int device_open_excl(struct crypt_device *cd, struct device *device, int flags);
void device_release_excl(struct crypt_device *cd, struct device *device);
void device_disable_direct_io(struct device *device);
int device_is_identical(struct device *device1, struct device *device2);
int device_is_rotational(struct device *device);
int device_is_dax(struct device *device);
size_t device_alignment(struct device *device);
int device_direct_io(const struct device *device);
int device_fallocate(struct device *device, uint64_t size);
void device_sync(struct crypt_device *cd, struct device *device);
int device_check_size(struct crypt_device *cd,
		      struct device *device,
		      uint64_t req_offset, int falloc);
void device_set_block_size(struct device *device, size_t size);
size_t device_optimal_encryption_sector_size(struct crypt_device *cd, struct device *device);

int device_open_locked(struct crypt_device *cd, struct device *device, int flags);
int device_read_lock(struct crypt_device *cd, struct device *device);
int device_write_lock(struct crypt_device *cd, struct device *device);
void device_read_unlock(struct crypt_device *cd, struct device *device);
void device_write_unlock(struct crypt_device *cd, struct device *device);
bool device_is_locked(struct device *device);

enum devcheck { DEV_OK = 0, DEV_EXCL = 1 };
int device_check_access(struct crypt_device *cd,
			struct device *device,
			enum devcheck device_check);
int device_block_adjust(struct crypt_device *cd,
			struct device *device,
			enum devcheck device_check,
			uint64_t device_offset,
			uint64_t *size,
			uint32_t *flags);
size_t size_round_up(size_t size, size_t block);

int create_or_reload_device(struct crypt_device *cd, const char *name,
		     const char *type, struct crypt_dm_active_device *dmd);

int create_or_reload_device_with_integrity(struct crypt_device *cd, const char *name,
		     const char *type, struct crypt_dm_active_device *dmd,
		     struct crypt_dm_active_device *dmdi);

/* Receive backend devices from context helpers */
struct device *crypt_metadata_device(struct crypt_device *cd);
struct device *crypt_data_device(struct crypt_device *cd);

uint64_t crypt_get_metadata_size_bytes(struct crypt_device *cd);
uint64_t crypt_get_keyslots_size_bytes(struct crypt_device *cd);
uint64_t crypt_get_data_offset_sectors(struct crypt_device *cd);

int crypt_confirm(struct crypt_device *cd, const char *msg);

char *crypt_lookup_dev(const char *dev_id);
int crypt_dev_is_rotational(int major, int minor);
int crypt_dev_is_dax(int major, int minor);
int crypt_dev_is_partition(const char *dev_path);
char *crypt_get_partition_device(const char *dev_path, uint64_t offset, uint64_t size);
char *crypt_get_base_device(const char *dev_path);
uint64_t crypt_dev_partition_offset(const char *dev_path);
int lookup_by_disk_id(const char *dm_uuid);
int lookup_by_sysfs_uuid_field(const char *dm_uuid);
int crypt_uuid_cmp(const char *dm_uuid, const char *hdr_uuid);

size_t crypt_getpagesize(void);
unsigned crypt_cpusonline(void);
uint64_t crypt_getphysmemory_kb(void);
uint64_t crypt_getphysmemoryfree_kb(void);
bool crypt_swapavailable(void);

int init_crypto(struct crypt_device *ctx);

#define log_dbg(c, x...) crypt_logf(c, CRYPT_LOG_DEBUG, x)
#define log_std(c, x...) crypt_logf(c, CRYPT_LOG_NORMAL, x)
#define log_verbose(c, x...) crypt_logf(c, CRYPT_LOG_VERBOSE, x)
#define log_err(c, x...) crypt_logf(c, CRYPT_LOG_ERROR, x)

int crypt_get_debug_level(void);

void crypt_process_priority(struct crypt_device *cd, int *priority, bool raise);

int crypt_metadata_locking_enabled(void);

int crypt_random_init(struct crypt_device *ctx);
int crypt_random_get(struct crypt_device *ctx, char *buf, size_t len, int quality);
void crypt_random_exit(void);
int crypt_random_default_key_rng(void);

int crypt_plain_hash(struct crypt_device *cd,
		     const char *hash_name,
		     char *key, size_t key_size,
		     const char *passphrase, size_t passphrase_size);
int PLAIN_activate(struct crypt_device *cd,
		     const char *name,
		     struct volume_key *vk,
		     uint64_t size,
		     uint32_t flags);

void *crypt_get_hdr(struct crypt_device *cd, const char *type);
void crypt_set_luks2_reencrypt(struct crypt_device *cd, struct luks2_reencrypt *rh);
struct luks2_reencrypt *crypt_get_luks2_reencrypt(struct crypt_device *cd);

int onlyLUKS2(struct crypt_device *cd);
int onlyLUKS2mask(struct crypt_device *cd, uint32_t mask);

int crypt_wipe_device(struct crypt_device *cd,
	struct device *device,
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr);

/* Internal integrity helpers */
const char *crypt_get_integrity(struct crypt_device *cd);
int crypt_get_integrity_key_size(struct crypt_device *cd);
int crypt_get_integrity_tag_size(struct crypt_device *cd);

int crypt_key_in_keyring(struct crypt_device *cd);
void crypt_set_key_in_keyring(struct crypt_device *cd, unsigned key_in_keyring);
int crypt_volume_key_load_in_keyring(struct crypt_device *cd, struct volume_key *vk);
int crypt_use_keyring_for_vk(struct crypt_device *cd);
void crypt_drop_keyring_key_by_description(struct crypt_device *cd, const char *key_description, key_type_t ktype);
void crypt_drop_keyring_key(struct crypt_device *cd, struct volume_key *vks);

static inline uint64_t compact_version(uint16_t major, uint16_t minor, uint16_t patch, uint16_t release)
{
	return (uint64_t)release | ((uint64_t)patch << 16) | ((uint64_t)minor << 32) | ((uint64_t)major << 48);
}

int kernel_version(uint64_t *kversion);

int crypt_serialize_lock(struct crypt_device *cd);
void crypt_serialize_unlock(struct crypt_device *cd);

bool crypt_string_in(const char *str, char **list, size_t list_size);
int crypt_strcmp(const char *a, const char *b);
int crypt_compare_dm_devices(struct crypt_device *cd,
			       const struct crypt_dm_active_device *src,
			       const struct crypt_dm_active_device *tgt);
static inline void *crypt_zalloc(size_t size) { return calloc(1, size); }

static inline bool uint64_mult_overflow(uint64_t *u, uint64_t b, size_t size)
{
	*u = (uint64_t)b * size;
	if ((uint64_t)(*u / size) != b)
		return true;
	return false;
}

#endif /* INTERNAL_H */
