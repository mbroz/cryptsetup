/*
 * LUKS - Linux Unified Key Setup
 *
 * Copyright (C) 2004-2006 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2020 Milan Broz
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

#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <uuid/uuid.h>

#include "luks.h"
#include "af.h"
#include "internal.h"

int LUKS_keyslot_area(const struct luks_phdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if(keyslot >= LUKS_NUMKEYS || keyslot < 0)
		return -EINVAL;

	*offset = (uint64_t)hdr->keyblock[keyslot].keyMaterialOffset * SECTOR_SIZE;
	*length = AF_split_sectors(hdr->keyBytes, LUKS_STRIPES) * SECTOR_SIZE;

	return 0;
}

/* insertsort: because the array has 8 elements and it's mostly sorted. that's why */
static void LUKS_sort_keyslots(const struct luks_phdr *hdr, int *array)
{
	int i, j, x;

	for (i = 1; i < LUKS_NUMKEYS; i++) {
		j = i;
		while (j > 0 && hdr->keyblock[array[j-1]].keyMaterialOffset > hdr->keyblock[array[j]].keyMaterialOffset) {
			x = array[j];
			array[j] = array[j-1];
			array[j-1] = x;
			j--;
		}
	}
}

size_t LUKS_device_sectors(const struct luks_phdr *hdr)
{
	int sorted_areas[LUKS_NUMKEYS] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	LUKS_sort_keyslots(hdr, sorted_areas);

	return hdr->keyblock[sorted_areas[LUKS_NUMKEYS-1]].keyMaterialOffset + AF_split_sectors(hdr->keyBytes, LUKS_STRIPES);
}

size_t LUKS_keyslots_offset(const struct luks_phdr *hdr)
{
	int sorted_areas[LUKS_NUMKEYS] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	LUKS_sort_keyslots(hdr, sorted_areas);

	return hdr->keyblock[sorted_areas[0]].keyMaterialOffset;
}

static int LUKS_check_device_size(struct crypt_device *ctx, const struct luks_phdr *hdr, int falloc)
{
	struct device *device = crypt_metadata_device(ctx);
	uint64_t dev_sectors, hdr_sectors;

	if (!hdr->keyBytes)
		return -EINVAL;

	if (device_size(device, &dev_sectors)) {
		log_dbg(ctx, "Cannot get device size for device %s.", device_path(device));
		return -EIO;
	}

	dev_sectors >>= SECTOR_SHIFT;
	hdr_sectors = LUKS_device_sectors(hdr);
	log_dbg(ctx, "Key length %u, device size %" PRIu64 " sectors, header size %"
		PRIu64 " sectors.", hdr->keyBytes, dev_sectors, hdr_sectors);

	if (hdr_sectors > dev_sectors) {
		/* If it is header file, increase its size */
		if (falloc && !device_fallocate(device, hdr_sectors << SECTOR_SHIFT))
			return 0;

		log_err(ctx, _("Device %s is too small. (LUKS1 requires at least %" PRIu64 " bytes.)"),
			device_path(device), hdr_sectors * SECTOR_SIZE);
		return -EINVAL;
	}

	return 0;
}

static int LUKS_check_keyslots(struct crypt_device *ctx, const struct luks_phdr *phdr)
{
	int i, prev, next, sorted_areas[LUKS_NUMKEYS] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	uint32_t secs_per_stripes = AF_split_sectors(phdr->keyBytes, LUKS_STRIPES);

	LUKS_sort_keyslots(phdr, sorted_areas);

	/* Check keyslot to prevent access outside of header and keyslot area */
	for (i = 0; i < LUKS_NUMKEYS; i++) {
		/* enforce stripes == 4000 */
		if (phdr->keyblock[i].stripes != LUKS_STRIPES) {
			log_dbg(ctx, "Invalid stripes count %u in keyslot %u.",
				phdr->keyblock[i].stripes, i);
			log_err(ctx, _("LUKS keyslot %u is invalid."), i);
			return -1;
		}

		/* First sectors is the header itself */
		if (phdr->keyblock[i].keyMaterialOffset * SECTOR_SIZE < sizeof(*phdr)) {
			log_dbg(ctx, "Invalid offset %u in keyslot %u.",
				phdr->keyblock[i].keyMaterialOffset, i);
			log_err(ctx, _("LUKS keyslot %u is invalid."), i);
			return -1;
		}

		/* Ignore following check for detached header where offset can be zero. */
		if (phdr->payloadOffset == 0)
			continue;

		if (phdr->payloadOffset <= phdr->keyblock[i].keyMaterialOffset) {
			log_dbg(ctx, "Invalid offset %u in keyslot %u (beyond data area offset %u).",
				phdr->keyblock[i].keyMaterialOffset, i,
				phdr->payloadOffset);
			log_err(ctx, _("LUKS keyslot %u is invalid."), i);
			return -1;
		}

		if (phdr->payloadOffset < (phdr->keyblock[i].keyMaterialOffset + secs_per_stripes)) {
			log_dbg(ctx, "Invalid keyslot size %u (offset %u, stripes %u) in "
				"keyslot %u (beyond data area offset %u).",
				secs_per_stripes,
				phdr->keyblock[i].keyMaterialOffset,
				phdr->keyblock[i].stripes,
				i, phdr->payloadOffset);
			log_err(ctx, _("LUKS keyslot %u is invalid."), i);
			return -1;
		}
	}

	/* check no keyslot overlaps with each other */
	for (i = 1; i < LUKS_NUMKEYS; i++) {
		prev = sorted_areas[i-1];
		next = sorted_areas[i];
		if (phdr->keyblock[next].keyMaterialOffset <
		    (phdr->keyblock[prev].keyMaterialOffset + secs_per_stripes)) {
			log_dbg(ctx, "Not enough space in LUKS keyslot %d.", prev);
			log_err(ctx, _("LUKS keyslot %u is invalid."), prev);
			return -1;
		}
	}
	/* do not check last keyslot on purpose, it must be tested in device size check */

	return 0;
}

static const char *dbg_slot_state(crypt_keyslot_info ki)
{
	switch(ki) {
	case CRYPT_SLOT_INACTIVE:
		return "INACTIVE";
	case CRYPT_SLOT_ACTIVE:
		return "ACTIVE";
	case CRYPT_SLOT_ACTIVE_LAST:
		return "ACTIVE_LAST";
	case CRYPT_SLOT_INVALID:
	default:
		return "INVALID";
	}
}

int LUKS_hdr_backup(const char *backup_file, struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	struct luks_phdr hdr;
	int fd, devfd, r = 0;
	size_t hdr_size;
	size_t buffer_size;
	ssize_t ret;
	char *buffer = NULL;

	r = LUKS_read_phdr(&hdr, 1, 0, ctx);
	if (r)
		return r;

	hdr_size = LUKS_device_sectors(&hdr) << SECTOR_SHIFT;
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer || hdr_size < LUKS_ALIGN_KEYSLOTS || hdr_size > buffer_size) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg(ctx, "Storing backup of header (%zu bytes) and keyslot area (%zu bytes).",
		sizeof(hdr), hdr_size - LUKS_ALIGN_KEYSLOTS);

	log_dbg(ctx, "Output backup file size: %zu bytes.", buffer_size);

	devfd = device_open(ctx, device, O_RDONLY);
	if (devfd < 0) {
		log_err(ctx, _("Device %s is not a valid LUKS device."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (read_lseek_blockwise(devfd, device_block_size(ctx, device), device_alignment(device),
			   buffer, hdr_size, 0) < (ssize_t)hdr_size) {
		r = -EIO;
		goto out;
	}

	/* Wipe unused area, so backup cannot contain old signatures */
	if (hdr.keyblock[0].keyMaterialOffset * SECTOR_SIZE == LUKS_ALIGN_KEYSLOTS)
		memset(buffer + sizeof(hdr), 0, LUKS_ALIGN_KEYSLOTS - sizeof(hdr));

	fd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (fd == -1) {
		if (errno == EEXIST)
			log_err(ctx, _("Requested header backup file %s already exists."), backup_file);
		else
			log_err(ctx, _("Cannot create header backup file %s."), backup_file);
		r = -EINVAL;
		goto out;
	}
	ret = write_buffer(fd, buffer, buffer_size);
	close(fd);
	if (ret < (ssize_t)buffer_size) {
		log_err(ctx, _("Cannot write header backup file %s."), backup_file);
		r = -EIO;
		goto out;
	}

	r = 0;
out:
	crypt_safe_memzero(&hdr, sizeof(hdr));
	crypt_safe_free(buffer);
	return r;
}

int LUKS_hdr_restore(
	const char *backup_file,
	struct luks_phdr *hdr,
	struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	int fd, r = 0, devfd = -1, diff_uuid = 0;
	ssize_t ret, buffer_size = 0;
	char *buffer = NULL, msg[200];
	struct luks_phdr hdr_file;

	r = LUKS_read_phdr_backup(backup_file, &hdr_file, 0, ctx);
	if (r == -ENOENT)
		return r;

	if (!r)
		buffer_size = LUKS_device_sectors(&hdr_file) << SECTOR_SHIFT;

	if (r || buffer_size < LUKS_ALIGN_KEYSLOTS) {
		log_err(ctx, _("Backup file does not contain valid LUKS header."));
		r = -EINVAL;
		goto out;
	}

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer) {
		r = -ENOMEM;
		goto out;
	}

	fd = open(backup_file, O_RDONLY);
	if (fd == -1) {
		log_err(ctx, _("Cannot open header backup file %s."), backup_file);
		r = -EINVAL;
		goto out;
	}

	ret = read_buffer(fd, buffer, buffer_size);
	close(fd);
	if (ret < buffer_size) {
		log_err(ctx, _("Cannot read header backup file %s."), backup_file);
		r = -EIO;
		goto out;
	}

	r = LUKS_read_phdr(hdr, 0, 0, ctx);
	if (r == 0) {
		log_dbg(ctx, "Device %s already contains LUKS header, checking UUID and offset.", device_path(device));
		if(hdr->payloadOffset != hdr_file.payloadOffset ||
		   hdr->keyBytes != hdr_file.keyBytes) {
			log_err(ctx, _("Data offset or key size differs on device and backup, restore failed."));
			r = -EINVAL;
			goto out;
		}
		if (memcmp(hdr->uuid, hdr_file.uuid, UUID_STRING_L))
			diff_uuid = 1;
	}

	if (snprintf(msg, sizeof(msg), _("Device %s %s%s"), device_path(device),
		 r ? _("does not contain LUKS header. Replacing header can destroy data on that device.") :
		     _("already contains LUKS header. Replacing header will destroy existing keyslots."),
		     diff_uuid ? _("\nWARNING: real device header has different UUID than backup!") : "") < 0) {
		r = -ENOMEM;
		goto out;
	}

	if (!crypt_confirm(ctx, msg)) {
		r = -EINVAL;
		goto out;
	}

	log_dbg(ctx, "Storing backup of header (%zu bytes) and keyslot area (%zu bytes) to device %s.",
		sizeof(*hdr), buffer_size - LUKS_ALIGN_KEYSLOTS, device_path(device));

	devfd = device_open(ctx, device, O_RDWR);
	if (devfd < 0) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied."),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s."), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (write_lseek_blockwise(devfd, device_block_size(ctx, device), device_alignment(device),
			    buffer, buffer_size, 0) < buffer_size) {
		r = -EIO;
		goto out;
	}

	/* Be sure to reload new data */
	r = LUKS_read_phdr(hdr, 1, 0, ctx);
out:
	device_sync(ctx, device);
	crypt_safe_free(buffer);
	return r;
}

/* This routine should do some just basic recovery for known problems. */
static int _keyslot_repair(struct luks_phdr *phdr, struct crypt_device *ctx)
{
	struct luks_phdr temp_phdr;
	const unsigned char *sector = (const unsigned char*)phdr;
	struct volume_key *vk;
	int i, bad, r, need_write = 0;

	if (phdr->keyBytes != 16 && phdr->keyBytes != 32 && phdr->keyBytes != 64) {
		log_err(ctx, _("Non standard key size, manual repair required."));
		return -EINVAL;
	}
	/* cryptsetup 1.0 did not align to 4k, cannot repair this one */
	if (LUKS_keyslots_offset(phdr) < (LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE)) {
		log_err(ctx, _("Non standard keyslots alignment, manual repair required."));
		return -EINVAL;
	}

	r = LUKS_check_cipher(ctx, phdr->keyBytes, phdr->cipherName, phdr->cipherMode);
	if (r < 0)
		return -EINVAL;

	vk = crypt_alloc_volume_key(phdr->keyBytes, NULL);

	log_verbose(ctx, _("Repairing keyslots."));

	log_dbg(ctx, "Generating second header with the same parameters for check.");
	/* cipherName, cipherMode, hashSpec, uuid are already null terminated */
	/* payloadOffset - cannot check */
	r = LUKS_generate_phdr(&temp_phdr, vk, phdr->cipherName, phdr->cipherMode,
			       phdr->hashSpec, phdr->uuid,
			       phdr->payloadOffset * SECTOR_SIZE, 0, 0, ctx);
	if (r < 0)
		goto out;

	for(i = 0; i < LUKS_NUMKEYS; ++i) {
		if (phdr->keyblock[i].active == LUKS_KEY_ENABLED)  {
			log_dbg(ctx, "Skipping repair for active keyslot %i.", i);
			continue;
		}

		bad = 0;
		if (phdr->keyblock[i].keyMaterialOffset != temp_phdr.keyblock[i].keyMaterialOffset) {
			log_err(ctx, _("Keyslot %i: offset repaired (%u -> %u)."), i,
				(unsigned)phdr->keyblock[i].keyMaterialOffset,
				(unsigned)temp_phdr.keyblock[i].keyMaterialOffset);
			phdr->keyblock[i].keyMaterialOffset = temp_phdr.keyblock[i].keyMaterialOffset;
			bad = 1;
		}

		if (phdr->keyblock[i].stripes != temp_phdr.keyblock[i].stripes) {
			log_err(ctx, _("Keyslot %i: stripes repaired (%u -> %u)."), i,
				(unsigned)phdr->keyblock[i].stripes,
				(unsigned)temp_phdr.keyblock[i].stripes);
			phdr->keyblock[i].stripes = temp_phdr.keyblock[i].stripes;
			bad = 1;
		}

		/* Known case - MSDOS partition table signature */
		if (i == 6 && sector[0x1fe] == 0x55 && sector[0x1ff] == 0xaa) {
			log_err(ctx, _("Keyslot %i: bogus partition signature."), i);
			bad = 1;
		}

		if(bad) {
			log_err(ctx, _("Keyslot %i: salt wiped."), i);
			phdr->keyblock[i].active = LUKS_KEY_DISABLED;
			memset(&phdr->keyblock[i].passwordSalt, 0x00, LUKS_SALTSIZE);
			phdr->keyblock[i].passwordIterations = 0;
		}

		if (bad)
			need_write = 1;
	}

	/*
	 * check repair result before writing because repair can't fix out of order
	 * keyslot offsets and would corrupt header again
	 */
	if (LUKS_check_keyslots(ctx, phdr))
		r = -EINVAL;
	else if (need_write) {
		log_verbose(ctx, _("Writing LUKS header to disk."));
		r = LUKS_write_phdr(phdr, ctx);
	}
out:
	if (r)
		log_err(ctx, _("Repair failed."));
	crypt_free_volume_key(vk);
	crypt_safe_memzero(&temp_phdr, sizeof(temp_phdr));
	return r;
}

static int _check_and_convert_hdr(const char *device,
				  struct luks_phdr *hdr,
				  int require_luks_device,
				  int repair,
				  struct crypt_device *ctx)
{
	int r = 0;
	unsigned int i;
	char luksMagic[] = LUKS_MAGIC;

	if(memcmp(hdr->magic, luksMagic, LUKS_MAGIC_L)) { /* Check magic */
		log_dbg(ctx, "LUKS header not detected.");
		if (require_luks_device)
			log_err(ctx, _("Device %s is not a valid LUKS device."), device);
		return -EINVAL;
	} else if((hdr->version = ntohs(hdr->version)) != 1) {	/* Convert every uint16/32_t item from network byte order */
		log_err(ctx, _("Unsupported LUKS version %d."), hdr->version);
		return -EINVAL;
	}

	hdr->hashSpec[LUKS_HASHSPEC_L - 1] = '\0';
	if (crypt_hmac_size(hdr->hashSpec) < LUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested LUKS hash %s is not supported."), hdr->hashSpec);
		return -EINVAL;
	}

	/* Header detected */
	hdr->payloadOffset      = ntohl(hdr->payloadOffset);
	hdr->keyBytes           = ntohl(hdr->keyBytes);
	hdr->mkDigestIterations = ntohl(hdr->mkDigestIterations);

	for(i = 0; i < LUKS_NUMKEYS; ++i) {
		hdr->keyblock[i].active             = ntohl(hdr->keyblock[i].active);
		hdr->keyblock[i].passwordIterations = ntohl(hdr->keyblock[i].passwordIterations);
		hdr->keyblock[i].keyMaterialOffset  = ntohl(hdr->keyblock[i].keyMaterialOffset);
		hdr->keyblock[i].stripes            = ntohl(hdr->keyblock[i].stripes);
	}

	if (LUKS_check_keyslots(ctx, hdr))
		r = -EINVAL;

	/* Avoid unterminated strings */
	hdr->cipherName[LUKS_CIPHERNAME_L - 1] = '\0';
	hdr->cipherMode[LUKS_CIPHERMODE_L - 1] = '\0';
	hdr->uuid[UUID_STRING_L - 1] = '\0';

	if (repair) {
		if (r == -EINVAL)
			r = _keyslot_repair(hdr, ctx);
		else
			log_verbose(ctx, _("No known problems detected for LUKS header."));
	}

	return r;
}

static void _to_lower(char *str, unsigned max_len)
{
	for(; *str && max_len; str++, max_len--)
		if (isupper(*str))
			*str = tolower(*str);
}

static void LUKS_fix_header_compatible(struct luks_phdr *header)
{
	/* Old cryptsetup expects "sha1", gcrypt allows case insensitive names,
	 * so always convert hash to lower case in header */
	_to_lower(header->hashSpec, LUKS_HASHSPEC_L);

	/* ECB mode does not use IV but dmcrypt silently allows it.
	 * Drop any IV here if ECB is used (that is not secure anyway).*/
	if (!strncmp(header->cipherMode, "ecb-", 4)) {
		memset(header->cipherMode, 0, LUKS_CIPHERMODE_L);
		strcpy(header->cipherMode, "ecb");
	}
}

int LUKS_read_phdr_backup(const char *backup_file,
			  struct luks_phdr *hdr,
			  int require_luks_device,
			  struct crypt_device *ctx)
{
	ssize_t hdr_size = sizeof(struct luks_phdr);
	int devfd = 0, r = 0;

	log_dbg(ctx, "Reading LUKS header of size %d from backup file %s",
		(int)hdr_size, backup_file);

	devfd = open(backup_file, O_RDONLY);
	if (devfd == -1) {
		log_err(ctx, _("Cannot open header backup file %s."), backup_file);
		return -ENOENT;
	}

	if (read_buffer(devfd, hdr, hdr_size) < hdr_size)
		r = -EIO;
	else {
		LUKS_fix_header_compatible(hdr);
		r = _check_and_convert_hdr(backup_file, hdr,
					   require_luks_device, 0, ctx);
	}

	close(devfd);
	return r;
}

int LUKS_read_phdr(struct luks_phdr *hdr,
		   int require_luks_device,
		   int repair,
		   struct crypt_device *ctx)
{
	int devfd, r = 0;
	struct device *device = crypt_metadata_device(ctx);
	ssize_t hdr_size = sizeof(struct luks_phdr);

	/* LUKS header starts at offset 0, first keyslot on LUKS_ALIGN_KEYSLOTS */
	assert(sizeof(struct luks_phdr) <= LUKS_ALIGN_KEYSLOTS);

	/* Stripes count cannot be changed without additional code fixes yet */
	assert(LUKS_STRIPES == 4000);

	if (repair && !require_luks_device)
		return -EINVAL;

	log_dbg(ctx, "Reading LUKS header of size %zu from device %s",
		hdr_size, device_path(device));

	devfd = device_open(ctx, device, O_RDONLY);
	if (devfd < 0) {
		log_err(ctx, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	if (read_lseek_blockwise(devfd, device_block_size(ctx, device), device_alignment(device),
			   hdr, hdr_size, 0) < hdr_size)
		r = -EIO;
	else
		r = _check_and_convert_hdr(device_path(device), hdr, require_luks_device,
					   repair, ctx);

	if (!r)
		r = LUKS_check_device_size(ctx, hdr, 0);

	/*
	 * Cryptsetup 1.0.0 did not align keyslots to 4k (very rare version).
	 * Disable direct-io to avoid possible IO errors if underlying device
	 * has bigger sector size.
	 */
	if (!r && hdr->keyblock[0].keyMaterialOffset * SECTOR_SIZE < LUKS_ALIGN_KEYSLOTS) {
		log_dbg(ctx, "Old unaligned LUKS keyslot detected, disabling direct-io.");
		device_disable_direct_io(device);
	}

	return r;
}

int LUKS_write_phdr(struct luks_phdr *hdr,
		    struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	ssize_t hdr_size = sizeof(struct luks_phdr);
	int devfd = 0;
	unsigned int i;
	struct luks_phdr convHdr;
	int r;

	log_dbg(ctx, "Updating LUKS header of size %zu on device %s",
		sizeof(struct luks_phdr), device_path(device));

	r = LUKS_check_device_size(ctx, hdr, 1);
	if (r)
		return r;

	devfd = device_open(ctx, device, O_RDWR);
	if (devfd < 0) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied."),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s."), device_path(device));
		return -EINVAL;
	}

	memcpy(&convHdr, hdr, hdr_size);
	memset(&convHdr._padding, 0, sizeof(convHdr._padding));

	/* Convert every uint16/32_t item to network byte order */
	convHdr.version            = htons(hdr->version);
	convHdr.payloadOffset      = htonl(hdr->payloadOffset);
	convHdr.keyBytes           = htonl(hdr->keyBytes);
	convHdr.mkDigestIterations = htonl(hdr->mkDigestIterations);
	for(i = 0; i < LUKS_NUMKEYS; ++i) {
		convHdr.keyblock[i].active             = htonl(hdr->keyblock[i].active);
		convHdr.keyblock[i].passwordIterations = htonl(hdr->keyblock[i].passwordIterations);
		convHdr.keyblock[i].keyMaterialOffset  = htonl(hdr->keyblock[i].keyMaterialOffset);
		convHdr.keyblock[i].stripes            = htonl(hdr->keyblock[i].stripes);
	}

	r = write_lseek_blockwise(devfd, device_block_size(ctx, device), device_alignment(device),
			    &convHdr, hdr_size, 0) < hdr_size ? -EIO : 0;
	if (r)
		log_err(ctx, _("Error during update of LUKS header on device %s."), device_path(device));

	device_sync(ctx, device);

	/* Re-read header from disk to be sure that in-memory and on-disk data are the same. */
	if (!r) {
		r = LUKS_read_phdr(hdr, 1, 0, ctx);
		if (r)
			log_err(ctx, _("Error re-reading LUKS header after update on device %s."),
				device_path(device));
	}

	return r;
}

/* Check that kernel supports requested cipher by decryption of one sector */
int LUKS_check_cipher(struct crypt_device *ctx, size_t keylength, const char *cipher, const char *cipher_mode)
{
	int r;
	struct volume_key *empty_key;
	char buf[SECTOR_SIZE];

	log_dbg(ctx, "Checking if cipher %s-%s is usable.", cipher, cipher_mode);

	empty_key = crypt_alloc_volume_key(keylength, NULL);
	if (!empty_key)
		return -ENOMEM;

	/* No need to get KEY quality random but it must avoid known weak keys. */
	r = crypt_random_get(ctx, empty_key->key, empty_key->keylength, CRYPT_RND_NORMAL);
	if (!r)
		r = LUKS_decrypt_from_storage(buf, sizeof(buf), cipher, cipher_mode, empty_key, 0, ctx);

	crypt_free_volume_key(empty_key);
	crypt_safe_memzero(buf, sizeof(buf));
	return r;
}

int LUKS_generate_phdr(struct luks_phdr *header,
	const struct volume_key *vk,
	const char *cipherName,
	const char *cipherMode,
	const char *hashSpec,
	const char *uuid,
	uint64_t data_offset,        /* in bytes */
	uint64_t align_offset,       /* in bytes */
	uint64_t required_alignment, /* in bytes */
	struct crypt_device *ctx)
{
	int i, r;
	size_t keyslot_sectors, header_sectors;
	uuid_t partitionUuid;
	struct crypt_pbkdf_type *pbkdf;
	double PBKDF2_temp;
	char luksMagic[] = LUKS_MAGIC;

	if (data_offset % SECTOR_SIZE || align_offset % SECTOR_SIZE ||
	    required_alignment % SECTOR_SIZE)
		return -EINVAL;

	memset(header, 0, sizeof(struct luks_phdr));

	keyslot_sectors = AF_split_sectors(vk->keylength, LUKS_STRIPES);
	header_sectors = LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;

	for (i = 0; i < LUKS_NUMKEYS; i++) {
		header->keyblock[i].active = LUKS_KEY_DISABLED;
		header->keyblock[i].keyMaterialOffset = header_sectors;
		header->keyblock[i].stripes = LUKS_STRIPES;
		header_sectors = size_round_up(header_sectors + keyslot_sectors,
					       LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
	}
	/* In sector is now size of all keyslot material space */

	/* Data offset has priority */
	if (data_offset)
		header->payloadOffset = data_offset / SECTOR_SIZE;
	else if (required_alignment) {
		header->payloadOffset = size_round_up(header_sectors, (required_alignment / SECTOR_SIZE));
		header->payloadOffset += (align_offset / SECTOR_SIZE);
	} else
		header->payloadOffset = 0;

	if (header->payloadOffset && header->payloadOffset < header_sectors) {
		log_err(ctx, _("Data offset for LUKS header must be "
			       "either 0 or higher than header size."));
		return -EINVAL;
	}

	if (crypt_hmac_size(hashSpec) < LUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested LUKS hash %s is not supported."), hashSpec);
		return -EINVAL;
	}

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(ctx, _("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	/* Set Magic */
	memcpy(header->magic,luksMagic,LUKS_MAGIC_L);
	header->version=1;
	strncpy(header->cipherName,cipherName,LUKS_CIPHERNAME_L-1);
	strncpy(header->cipherMode,cipherMode,LUKS_CIPHERMODE_L-1);
	strncpy(header->hashSpec,hashSpec,LUKS_HASHSPEC_L-1);

	header->keyBytes=vk->keylength;

	LUKS_fix_header_compatible(header);

	log_dbg(ctx, "Generating LUKS header version %d using hash %s, %s, %s, MK %d bytes",
		header->version, header->hashSpec ,header->cipherName, header->cipherMode,
		header->keyBytes);

	r = crypt_random_get(ctx, header->mkDigestSalt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if(r < 0) {
		log_err(ctx, _("Cannot create LUKS header: reading random salt failed."));
		return r;
	}

	/* Compute master key digest */
	pbkdf = crypt_get_pbkdf(ctx);
	r = crypt_benchmark_pbkdf_internal(ctx, pbkdf, vk->keylength);
	if (r < 0)
		return r;
	assert(pbkdf->iterations);

	if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK && pbkdf->time_ms == 0)
		PBKDF2_temp = LUKS_MKD_ITERATIONS_MIN;
	else	/* iterations per ms * LUKS_MKD_ITERATIONS_MS */
		PBKDF2_temp = (double)pbkdf->iterations * LUKS_MKD_ITERATIONS_MS / pbkdf->time_ms;

	if (PBKDF2_temp > (double)UINT32_MAX)
		return -EINVAL;
	header->mkDigestIterations = at_least((uint32_t)PBKDF2_temp, LUKS_MKD_ITERATIONS_MIN);
	assert(header->mkDigestIterations);

	r = crypt_pbkdf(CRYPT_KDF_PBKDF2, header->hashSpec, vk->key,vk->keylength,
			header->mkDigestSalt, LUKS_SALTSIZE,
			header->mkDigest,LUKS_DIGESTSIZE,
			header->mkDigestIterations, 0, 0);
	if (r < 0) {
		log_err(ctx, _("Cannot create LUKS header: header digest failed (using hash %s)."),
			header->hashSpec);
		return r;
	}

        uuid_unparse(partitionUuid, header->uuid);

	log_dbg(ctx, "Data offset %d, UUID %s, digest iterations %" PRIu32,
		header->payloadOffset, header->uuid, header->mkDigestIterations);

	return 0;
}

int LUKS_hdr_uuid_set(
	struct luks_phdr *hdr,
	const char *uuid,
	struct crypt_device *ctx)
{
	uuid_t partitionUuid;

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(ctx, _("Wrong LUKS UUID format provided."));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	uuid_unparse(partitionUuid, hdr->uuid);

	return LUKS_write_phdr(hdr, ctx);
}

int LUKS_set_key(unsigned int keyIndex,
		 const char *password, size_t passwordLen,
		 struct luks_phdr *hdr, struct volume_key *vk,
		 struct crypt_device *ctx)
{
	struct volume_key *derived_key;
	char *AfKey = NULL;
	size_t AFEKSize;
	struct crypt_pbkdf_type *pbkdf;
	int r;

	if(hdr->keyblock[keyIndex].active != LUKS_KEY_DISABLED) {
		log_err(ctx, _("Key slot %d active, purge first."), keyIndex);
		return -EINVAL;
	}

	/* LUKS keyslot has always at least 4000 stripes according to specification */
	if(hdr->keyblock[keyIndex].stripes < 4000) {
	        log_err(ctx, _("Key slot %d material includes too few stripes. Header manipulation?"),
			keyIndex);
	         return -EINVAL;
	}

	log_dbg(ctx, "Calculating data for key slot %d", keyIndex);
	pbkdf = crypt_get_pbkdf(ctx);
	r = crypt_benchmark_pbkdf_internal(ctx, pbkdf, vk->keylength);
	if (r < 0)
		return r;
	assert(pbkdf->iterations);

	/*
	 * Final iteration count is at least LUKS_SLOT_ITERATIONS_MIN
	 */
	hdr->keyblock[keyIndex].passwordIterations =
		at_least(pbkdf->iterations, LUKS_SLOT_ITERATIONS_MIN);
	log_dbg(ctx, "Key slot %d use %" PRIu32 " password iterations.", keyIndex,
		hdr->keyblock[keyIndex].passwordIterations);

	derived_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!derived_key)
		return -ENOMEM;

	r = crypt_random_get(ctx, hdr->keyblock[keyIndex].passwordSalt,
		       LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		goto out;

	r = crypt_pbkdf(CRYPT_KDF_PBKDF2, hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, LUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations, 0, 0);
	if (r < 0)
		goto out;

	/*
	 * AF splitting, the masterkey stored in vk->key is split to AfKey
	 */
	assert(vk->keylength == hdr->keyBytes);
	AFEKSize = AF_split_sectors(vk->keylength, hdr->keyblock[keyIndex].stripes) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg(ctx, "Using hash %s for AF in key slot %d, %d stripes",
		hdr->hashSpec, keyIndex, hdr->keyblock[keyIndex].stripes);
	r = AF_split(ctx, vk->key, AfKey, vk->keylength, hdr->keyblock[keyIndex].stripes, hdr->hashSpec);
	if (r < 0)
		goto out;

	log_dbg(ctx, "Updating key slot %d [0x%04x] area.", keyIndex,
		hdr->keyblock[keyIndex].keyMaterialOffset << 9);
	/* Encryption via dm */
	r = LUKS_encrypt_to_storage(AfKey,
				    AFEKSize,
				    hdr->cipherName, hdr->cipherMode,
				    derived_key,
				    hdr->keyblock[keyIndex].keyMaterialOffset,
				    ctx);
	if (r < 0)
		goto out;

	/* Mark the key as active in phdr */
	r = LUKS_keyslot_set(hdr, (int)keyIndex, 1, ctx);
	if (r < 0)
		goto out;

	r = LUKS_write_phdr(hdr, ctx);
	if (r < 0)
		goto out;

	r = 0;
out:
	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	return r;
}

/* Check whether a volume key is invalid. */
int LUKS_verify_volume_key(const struct luks_phdr *hdr,
			   const struct volume_key *vk)
{
	char checkHashBuf[LUKS_DIGESTSIZE];

	if (crypt_pbkdf(CRYPT_KDF_PBKDF2, hdr->hashSpec, vk->key, vk->keylength,
			hdr->mkDigestSalt, LUKS_SALTSIZE,
			checkHashBuf, LUKS_DIGESTSIZE,
			hdr->mkDigestIterations, 0, 0) < 0)
		return -EINVAL;

	if (memcmp(checkHashBuf, hdr->mkDigest, LUKS_DIGESTSIZE))
		return -EPERM;

	return 0;
}

/* Try to open a particular key slot */
static int LUKS_open_key(unsigned int keyIndex,
		  const char *password,
		  size_t passwordLen,
		  struct luks_phdr *hdr,
		  struct volume_key *vk,
		  struct crypt_device *ctx)
{
	crypt_keyslot_info ki = LUKS_keyslot_info(hdr, keyIndex);
	struct volume_key *derived_key;
	char *AfKey;
	size_t AFEKSize;
	int r;

	log_dbg(ctx, "Trying to open key slot %d [%s].", keyIndex,
		dbg_slot_state(ki));

	if (ki < CRYPT_SLOT_ACTIVE)
		return -ENOENT;

	derived_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!derived_key)
		return -ENOMEM;

	assert(vk->keylength == hdr->keyBytes);
	AFEKSize = AF_split_sectors(vk->keylength, hdr->keyblock[keyIndex].stripes) * SECTOR_SIZE;
	AfKey = crypt_safe_alloc(AFEKSize);
	if (!AfKey) {
		r = -ENOMEM;
		goto out;
	}

	r = crypt_pbkdf(CRYPT_KDF_PBKDF2, hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, LUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations, 0, 0);
	if (r < 0) {
		log_err(ctx, _("Cannot open keyslot (using hash %s)."), hdr->hashSpec);
		goto out;
	}

	log_dbg(ctx, "Reading key slot %d area.", keyIndex);
	r = LUKS_decrypt_from_storage(AfKey,
				      AFEKSize,
				      hdr->cipherName, hdr->cipherMode,
				      derived_key,
				      hdr->keyblock[keyIndex].keyMaterialOffset,
				      ctx);
	if (r < 0)
		goto out;

	r = AF_merge(ctx, AfKey, vk->key, vk->keylength, hdr->keyblock[keyIndex].stripes, hdr->hashSpec);
	if (r < 0)
		goto out;

	r = LUKS_verify_volume_key(hdr, vk);

	/* Allow only empty passphrase with null cipher */
	if (!r && !strcmp(hdr->cipherName, "cipher_null") && passwordLen)
		r = -EPERM;
out:
	crypt_safe_free(AfKey);
	crypt_free_volume_key(derived_key);
	return r;
}

int LUKS_open_key_with_hdr(int keyIndex,
			   const char *password,
			   size_t passwordLen,
			   struct luks_phdr *hdr,
			   struct volume_key **vk,
			   struct crypt_device *ctx)
{
	unsigned int i, tried = 0;
	int r;

	*vk = crypt_alloc_volume_key(hdr->keyBytes, NULL);

	if (keyIndex >= 0) {
		r = LUKS_open_key(keyIndex, password, passwordLen, hdr, *vk, ctx);
		return (r < 0) ? r : keyIndex;
	}

	for (i = 0; i < LUKS_NUMKEYS; i++) {
		r = LUKS_open_key(i, password, passwordLen, hdr, *vk, ctx);
		if(r == 0)
			return i;

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot inactive */
		if ((r != -EPERM) && (r != -ENOENT))
			return r;
		if (r == -EPERM)
			tried++;
	}
	/* Warning, early returns above */
	return tried ? -EPERM : -ENOENT;
}

int LUKS_del_key(unsigned int keyIndex,
		 struct luks_phdr *hdr,
		 struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	unsigned int startOffset, endOffset;
	int r;

	r = LUKS_read_phdr(hdr, 1, 0, ctx);
	if (r)
		return r;

	r = LUKS_keyslot_set(hdr, keyIndex, 0, ctx);
	if (r) {
		log_err(ctx, _("Key slot %d is invalid, please select keyslot between 0 and %d."),
			keyIndex, LUKS_NUMKEYS - 1);
		return r;
	}

	/* secure deletion of key material */
	startOffset = hdr->keyblock[keyIndex].keyMaterialOffset;
	endOffset = startOffset + AF_split_sectors(hdr->keyBytes, hdr->keyblock[keyIndex].stripes);

	r = crypt_wipe_device(ctx, device, CRYPT_WIPE_SPECIAL, startOffset * SECTOR_SIZE,
			      (endOffset - startOffset) * SECTOR_SIZE,
			      (endOffset - startOffset) * SECTOR_SIZE, NULL, NULL);
	if (r) {
		if (r == -EACCES) {
			log_err(ctx, _("Cannot write to device %s, permission denied."),
				device_path(device));
			r = -EINVAL;
		} else
			log_err(ctx, _("Cannot wipe device %s."),
				device_path(device));
		return r;
	}

	/* Wipe keyslot info */
	memset(&hdr->keyblock[keyIndex].passwordSalt, 0, LUKS_SALTSIZE);
	hdr->keyblock[keyIndex].passwordIterations = 0;

	r = LUKS_write_phdr(hdr, ctx);

	return r;
}

crypt_keyslot_info LUKS_keyslot_info(struct luks_phdr *hdr, int keyslot)
{
	int i;

	if(keyslot >= LUKS_NUMKEYS || keyslot < 0)
		return CRYPT_SLOT_INVALID;

	if (hdr->keyblock[keyslot].active == LUKS_KEY_DISABLED)
		return CRYPT_SLOT_INACTIVE;

	if (hdr->keyblock[keyslot].active != LUKS_KEY_ENABLED)
		return CRYPT_SLOT_INVALID;

	for(i = 0; i < LUKS_NUMKEYS; i++)
		if(i != keyslot && hdr->keyblock[i].active == LUKS_KEY_ENABLED)
			return CRYPT_SLOT_ACTIVE;

	return CRYPT_SLOT_ACTIVE_LAST;
}

int LUKS_keyslot_find_empty(struct luks_phdr *hdr)
{
	int i;

	for (i = 0; i < LUKS_NUMKEYS; i++)
		if(hdr->keyblock[i].active == LUKS_KEY_DISABLED)
			break;

	if (i == LUKS_NUMKEYS)
		return -EINVAL;

	return i;
}

int LUKS_keyslot_active_count(struct luks_phdr *hdr)
{
	int i, num = 0;

	for (i = 0; i < LUKS_NUMKEYS; i++)
		if(hdr->keyblock[i].active == LUKS_KEY_ENABLED)
			num++;

	return num;
}

int LUKS_keyslot_set(struct luks_phdr *hdr, int keyslot, int enable, struct crypt_device *ctx)
{
	crypt_keyslot_info ki = LUKS_keyslot_info(hdr, keyslot);

	if (ki == CRYPT_SLOT_INVALID)
		return -EINVAL;

	hdr->keyblock[keyslot].active = enable ? LUKS_KEY_ENABLED : LUKS_KEY_DISABLED;
	log_dbg(ctx, "Key slot %d was %s in LUKS header.", keyslot, enable ? "enabled" : "disabled");
	return 0;
}

int LUKS1_activate(struct crypt_device *cd,
		   const char *name,
		   struct volume_key *vk,
		   uint32_t flags)
{
	int r;
	struct crypt_dm_active_device dmd = {
		.flags = flags,
		.uuid = crypt_get_uuid(cd),
	};

	r = dm_crypt_target_set(&dmd.segment, 0, dmd.size, crypt_data_device(cd),
			vk, crypt_get_cipher_spec(cd), crypt_get_iv_offset(cd),
			crypt_get_data_offset(cd), crypt_get_integrity(cd),
			crypt_get_integrity_tag_size(cd), crypt_get_sector_size(cd));
	if (!r)
		r = create_or_reload_device(cd, name, CRYPT_LUKS1, &dmd);

	dm_targets_free(cd, &dmd);

	return r;
}

int LUKS_wipe_header_areas(struct luks_phdr *hdr,
	struct crypt_device *ctx)
{
	int i, r;
	uint64_t offset, length;
	size_t wipe_block;

	/* Wipe complete header, keyslots and padding areas with zeroes. */
	offset = 0;
	length = (uint64_t)hdr->payloadOffset * SECTOR_SIZE;
	wipe_block = 1024 * 1024;

	/* On detached header or bogus header, wipe at least the first 4k */
	if (length == 0 || length > (LUKS_MAX_KEYSLOT_SIZE * LUKS_NUMKEYS)) {
		length = 4096;
		wipe_block = 4096;
	}

	log_dbg(ctx, "Wiping LUKS areas (0x%06" PRIx64 " - 0x%06" PRIx64") with zeroes.",
		offset, length + offset);

	r = crypt_wipe_device(ctx, crypt_metadata_device(ctx), CRYPT_WIPE_ZERO,
			      offset, length, wipe_block, NULL, NULL);
	if (r < 0)
		return r;

	/* Wipe keyslots areas */
	wipe_block = 1024 * 1024;
	for (i = 0; i < LUKS_NUMKEYS; i++) {
		r = LUKS_keyslot_area(hdr, i, &offset, &length);
		if (r < 0)
			return r;

		/* Ignore too big LUKS1 keyslots here */
		if (length > LUKS_MAX_KEYSLOT_SIZE ||
		    offset > (LUKS_MAX_KEYSLOT_SIZE - length))
			continue;

		if (length == 0 || offset < 4096)
			return -EINVAL;

		log_dbg(ctx, "Wiping keyslot %i area (0x%06" PRIx64 " - 0x%06" PRIx64") with random data.",
			i, offset, length + offset);

		r = crypt_wipe_device(ctx, crypt_metadata_device(ctx), CRYPT_WIPE_RANDOM,
				offset, length, wipe_block, NULL, NULL);
		if (r < 0)
			return r;
	}

	return r;
}

int LUKS_keyslot_pbkdf(struct luks_phdr *hdr, int keyslot, struct crypt_pbkdf_type *pbkdf)
{
	if (LUKS_keyslot_info(hdr, keyslot) < CRYPT_SLOT_ACTIVE)
		return -EINVAL;

	pbkdf->type = CRYPT_KDF_PBKDF2;
	pbkdf->hash = hdr->hashSpec;
	pbkdf->iterations = hdr->keyblock[keyslot].passwordIterations;
	pbkdf->max_memory_kb = 0;
	pbkdf->parallel_threads = 0;
	pbkdf->time_ms = 0;
	pbkdf->flags = 0;
	return 0;
}
