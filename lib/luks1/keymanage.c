/*
 * LUKS - Linux Unified Key Setup
 *
 * Copyright (C) 2004-2006, Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2014, Milan Broz
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
#include <fcntl.h>
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

/* Get size of struct luks_phdr with all keyslots material space */
static size_t LUKS_device_sectors(size_t keyLen)
{
	size_t keyslot_sectors, sector;
	int i;

	keyslot_sectors = AF_split_sectors(keyLen, LUKS_STRIPES);
	sector = LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;

	for (i = 0; i < LUKS_NUMKEYS; i++) {
		sector = size_round_up(sector, LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
		sector += keyslot_sectors;
	}

	return sector;
}

int LUKS_keyslot_area(struct luks_phdr *hdr,
	int keyslot,
	uint64_t *offset,
	uint64_t *length)
{
	if(keyslot >= LUKS_NUMKEYS || keyslot < 0)
		return -EINVAL;

	*offset = hdr->keyblock[keyslot].keyMaterialOffset * SECTOR_SIZE;
	*length = AF_split_sectors(hdr->keyBytes, LUKS_STRIPES) * SECTOR_SIZE;

	return 0;
}

static int LUKS_check_device_size(struct crypt_device *ctx, size_t keyLength)
{
	struct device *device = crypt_metadata_device(ctx);
	uint64_t dev_sectors, hdr_sectors;

	if (!keyLength)
		return -EINVAL;

	if(device_size(device, &dev_sectors)) {
		log_dbg("Cannot get device size for device %s.", device_path(device));
		return -EIO;
	}

	dev_sectors >>= SECTOR_SHIFT;
	hdr_sectors = LUKS_device_sectors(keyLength);
	log_dbg("Key length %zu, device size %" PRIu64 " sectors, header size %"
		PRIu64 " sectors.",keyLength, dev_sectors, hdr_sectors);

	if (hdr_sectors > dev_sectors) {
		log_err(ctx, _("Device %s is too small. (LUKS requires at least %" PRIu64 " bytes.)\n"),
			device_path(device), hdr_sectors * SECTOR_SIZE);
		return -EINVAL;
	}

	return 0;
}

/* Check keyslot to prevent access outside of header and keyslot area */
static int LUKS_check_keyslot_size(const struct luks_phdr *phdr, unsigned int keyIndex)
{
	uint32_t secs_per_stripes;

	/* First sectors is the header itself */
	if (phdr->keyblock[keyIndex].keyMaterialOffset * SECTOR_SIZE < sizeof(*phdr)) {
		log_dbg("Invalid offset %u in keyslot %u.",
			phdr->keyblock[keyIndex].keyMaterialOffset, keyIndex);
		return 1;
	}

	/* Ignore following check for detached header where offset can be zero. */
	if (phdr->payloadOffset == 0)
		return 0;

	if (phdr->payloadOffset <= phdr->keyblock[keyIndex].keyMaterialOffset) {
		log_dbg("Invalid offset %u in keyslot %u (beyond data area offset %u).",
			phdr->keyblock[keyIndex].keyMaterialOffset, keyIndex,
			phdr->payloadOffset);
		return 1;
	}

	secs_per_stripes = AF_split_sectors(phdr->keyBytes, phdr->keyblock[keyIndex].stripes);

	if (phdr->payloadOffset < (phdr->keyblock[keyIndex].keyMaterialOffset + secs_per_stripes)) {
		log_dbg("Invalid keyslot size %u (offset %u, stripes %u) in "
			"keyslot %u (beyond data area offset %u).",
			secs_per_stripes,
			phdr->keyblock[keyIndex].keyMaterialOffset,
			phdr->keyblock[keyIndex].stripes,
			keyIndex, phdr->payloadOffset);
		return 1;
	}

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
	int r = 0, devfd = -1;
	ssize_t hdr_size;
	ssize_t buffer_size;
	char *buffer = NULL;

	r = LUKS_read_phdr(&hdr, 1, 0, ctx);
	if (r)
		return r;

	hdr_size = LUKS_device_sectors(hdr.keyBytes) << SECTOR_SHIFT;
	buffer_size = size_round_up(hdr_size, crypt_getpagesize());

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer || hdr_size < LUKS_ALIGN_KEYSLOTS || hdr_size > buffer_size) {
		r = -ENOMEM;
		goto out;
	}

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes).",
		sizeof(hdr), hdr_size - LUKS_ALIGN_KEYSLOTS);

	log_dbg("Output backup file size: %zu bytes.", buffer_size);

	devfd = device_open(device, O_RDONLY);
	if(devfd == -1) {
		log_err(ctx, _("Device %s is not a valid LUKS device.\n"), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (read_blockwise(devfd, device_block_size(device), buffer, hdr_size) < hdr_size) {
		r = -EIO;
		goto out;
	}
	close(devfd);

	/* Wipe unused area, so backup cannot contain old signatures */
	if (hdr.keyblock[0].keyMaterialOffset * SECTOR_SIZE == LUKS_ALIGN_KEYSLOTS)
		memset(buffer + sizeof(hdr), 0, LUKS_ALIGN_KEYSLOTS - sizeof(hdr));

	devfd = open(backup_file, O_CREAT|O_EXCL|O_WRONLY, S_IRUSR);
	if (devfd == -1) {
		if (errno == EEXIST)
			log_err(ctx, _("Requested header backup file %s already exists.\n"), backup_file);
		else
			log_err(ctx, _("Cannot create header backup file %s.\n"), backup_file);
		r = -EINVAL;
		goto out;
	}
	if (write(devfd, buffer, buffer_size) < buffer_size) {
		log_err(ctx, _("Cannot write header backup file %s.\n"), backup_file);
		r = -EIO;
		goto out;
	}
	close(devfd);

	r = 0;
out:
	if (devfd != -1)
		close(devfd);
	memset(&hdr, 0, sizeof(hdr));
	crypt_safe_free(buffer);
	return r;
}

int LUKS_hdr_restore(
	const char *backup_file,
	struct luks_phdr *hdr,
	struct crypt_device *ctx)
{
	struct device *device = crypt_metadata_device(ctx);
	int r = 0, devfd = -1, diff_uuid = 0;
	ssize_t buffer_size = 0;
	char *buffer = NULL, msg[200];
	struct luks_phdr hdr_file;

	r = LUKS_read_phdr_backup(backup_file, &hdr_file, 0, ctx);
	if (r == -ENOENT)
		return r;

	if (!r)
		buffer_size = LUKS_device_sectors(hdr_file.keyBytes) << SECTOR_SHIFT;

	if (r || buffer_size < LUKS_ALIGN_KEYSLOTS) {
		log_err(ctx, _("Backup file doesn't contain valid LUKS header.\n"));
		r = -EINVAL;
		goto out;
	}

	buffer = crypt_safe_alloc(buffer_size);
	if (!buffer) {
		r = -ENOMEM;
		goto out;
	}

	devfd = open(backup_file, O_RDONLY);
	if (devfd == -1) {
		log_err(ctx, _("Cannot open header backup file %s.\n"), backup_file);
		r = -EINVAL;
		goto out;
	}

	if (read(devfd, buffer, buffer_size) < buffer_size) {
		log_err(ctx, _("Cannot read header backup file %s.\n"), backup_file);
		r = -EIO;
		goto out;
	}
	close(devfd);

	r = LUKS_read_phdr(hdr, 0, 0, ctx);
	if (r == 0) {
		log_dbg("Device %s already contains LUKS header, checking UUID and offset.", device_path(device));
		if(hdr->payloadOffset != hdr_file.payloadOffset ||
		   hdr->keyBytes != hdr_file.keyBytes) {
			log_err(ctx, _("Data offset or key size differs on device and backup, restore failed.\n"));
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

	log_dbg("Storing backup of header (%zu bytes) and keyslot area (%zu bytes) to device %s.",
		sizeof(*hdr), buffer_size - LUKS_ALIGN_KEYSLOTS, device_path(device));

	devfd = device_open(device, O_RDWR);
	if (devfd == -1) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
		r = -EINVAL;
		goto out;
	}

	if (write_blockwise(devfd, device_block_size(device), buffer, buffer_size) < buffer_size) {
		r = -EIO;
		goto out;
	}
	close(devfd);

	/* Be sure to reload new data */
	r = LUKS_read_phdr(hdr, 1, 0, ctx);
out:
	if (devfd != -1)
		close(devfd);
	crypt_safe_free(buffer);
	return r;
}

/* This routine should do some just basic recovery for known problems. */
static int _keyslot_repair(struct luks_phdr *phdr, struct crypt_device *ctx)
{
	struct luks_phdr temp_phdr;
	const unsigned char *sector = (const unsigned char*)phdr;
	struct volume_key *vk;
	uint64_t PBKDF2_per_sec = 1;
	int i, bad, r, need_write = 0;

	if (phdr->keyBytes != 16 && phdr->keyBytes != 32 && phdr->keyBytes != 64) {
		log_err(ctx, _("Non standard key size, manual repair required.\n"));
		return -EINVAL;
	}
	/* cryptsetup 1.0 did not align to 4k, cannot repair this one */
	if (phdr->keyblock[0].keyMaterialOffset < (LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE)) {
		log_err(ctx, _("Non standard keyslots alignment, manual repair required.\n"));
		return -EINVAL;
	}

	vk = crypt_alloc_volume_key(phdr->keyBytes, NULL);

	log_verbose(ctx, _("Repairing keyslots.\n"));

	log_dbg("Generating second header with the same parameters for check.");
	/* cipherName, cipherMode, hashSpec, uuid are already null terminated */
	/* payloadOffset - cannot check */
	r = LUKS_generate_phdr(&temp_phdr, vk, phdr->cipherName, phdr->cipherMode,
			       phdr->hashSpec,phdr->uuid, LUKS_STRIPES,
			       phdr->payloadOffset, 0,
			       1, &PBKDF2_per_sec,
			       1, ctx);
	if (r < 0) {
		log_err(ctx, _("Repair failed."));
		goto out;
	}

	for(i = 0; i < LUKS_NUMKEYS; ++i) {
		if (phdr->keyblock[i].active == LUKS_KEY_ENABLED)  {
			log_dbg("Skipping repair for active keyslot %i.", i);
			continue;
		}

		bad = 0;
		if (phdr->keyblock[i].keyMaterialOffset != temp_phdr.keyblock[i].keyMaterialOffset) {
			log_err(ctx, _("Keyslot %i: offset repaired (%u -> %u).\n"), i,
				(unsigned)phdr->keyblock[i].keyMaterialOffset,
				(unsigned)temp_phdr.keyblock[i].keyMaterialOffset);
			phdr->keyblock[i].keyMaterialOffset = temp_phdr.keyblock[i].keyMaterialOffset;
			bad = 1;
		}

		if (phdr->keyblock[i].stripes != temp_phdr.keyblock[i].stripes) {
			log_err(ctx, _("Keyslot %i: stripes repaired (%u -> %u).\n"), i,
				(unsigned)phdr->keyblock[i].stripes,
				(unsigned)temp_phdr.keyblock[i].stripes);
			phdr->keyblock[i].stripes = temp_phdr.keyblock[i].stripes;
			bad = 1;
		}

		/* Known case - MSDOS partition table signature */
		if (i == 6 && sector[0x1fe] == 0x55 && sector[0x1ff] == 0xaa) {
			log_err(ctx, _("Keyslot %i: bogus partition signature.\n"), i);
			bad = 1;
		}

		if(bad) {
			log_err(ctx, _("Keyslot %i: salt wiped.\n"), i);
			phdr->keyblock[i].active = LUKS_KEY_DISABLED;
			memset(&phdr->keyblock[i].passwordSalt, 0x00, LUKS_SALTSIZE);
			phdr->keyblock[i].passwordIterations = 0;
		}

		if (bad)
			need_write = 1;
	}

	if (need_write) {
		log_verbose(ctx, _("Writing LUKS header to disk.\n"));
		r = LUKS_write_phdr(phdr, ctx);
	}
out:
	crypt_free_volume_key(vk);
	memset(&temp_phdr, 0, sizeof(temp_phdr));
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
		log_dbg("LUKS header not detected.");
		if (require_luks_device)
			log_err(ctx, _("Device %s is not a valid LUKS device.\n"), device);
		return -EINVAL;
	} else if((hdr->version = ntohs(hdr->version)) != 1) {	/* Convert every uint16/32_t item from network byte order */
		log_err(ctx, _("Unsupported LUKS version %d.\n"), hdr->version);
		return -EINVAL;
	}

	hdr->hashSpec[LUKS_HASHSPEC_L - 1] = '\0';
	if (crypt_hmac_size(hdr->hashSpec) < LUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested LUKS hash %s is not supported.\n"), hdr->hashSpec);
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
		if (LUKS_check_keyslot_size(hdr, i)) {
			log_err(ctx, _("LUKS keyslot %u is invalid.\n"), i);
			r = -EINVAL;
		}
	}

	/* Avoid unterminated strings */
	hdr->cipherName[LUKS_CIPHERNAME_L - 1] = '\0';
	hdr->cipherMode[LUKS_CIPHERMODE_L - 1] = '\0';
	hdr->uuid[UUID_STRING_L - 1] = '\0';

	if (repair) {
		if (r == -EINVAL)
			r = _keyslot_repair(hdr, ctx);
		else
			log_verbose(ctx, _("No known problems detected for LUKS header.\n"));
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
	/* Old cryptsetup expects "sha1", gcrypt allows case insensistive names,
	 * so always convert hash to lower case in header */
	_to_lower(header->hashSpec, LUKS_HASHSPEC_L);
}

int LUKS_read_phdr_backup(const char *backup_file,
			  struct luks_phdr *hdr,
			  int require_luks_device,
			  struct crypt_device *ctx)
{
	ssize_t hdr_size = sizeof(struct luks_phdr);
	int devfd = 0, r = 0;

	log_dbg("Reading LUKS header of size %d from backup file %s",
		(int)hdr_size, backup_file);

	devfd = open(backup_file, O_RDONLY);
	if(-1 == devfd) {
		log_err(ctx, _("Cannot open header backup file %s.\n"), backup_file);
		return -ENOENT;
	}

	if (read(devfd, hdr, hdr_size) < hdr_size)
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
	struct device *device = crypt_metadata_device(ctx);
	ssize_t hdr_size = sizeof(struct luks_phdr);
	int devfd = 0, r = 0;

	/* LUKS header starts at offset 0, first keyslot on LUKS_ALIGN_KEYSLOTS */
	assert(sizeof(struct luks_phdr) <= LUKS_ALIGN_KEYSLOTS);

	/* Stripes count cannot be changed without additional code fixes yet */
	assert(LUKS_STRIPES == 4000);

	if (repair && !require_luks_device)
		return -EINVAL;

	log_dbg("Reading LUKS header of size %zu from device %s",
		hdr_size, device_path(device));

	devfd = device_open(device, O_RDONLY);
	if (devfd == -1) {
		log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
		return -EINVAL;
	}

	if (read_blockwise(devfd, device_block_size(device), hdr, hdr_size) < hdr_size)
		r = -EIO;
	else
		r = _check_and_convert_hdr(device_path(device), hdr, require_luks_device,
					   repair, ctx);

	if (!r)
		r = LUKS_check_device_size(ctx, hdr->keyBytes);

	close(devfd);
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

	log_dbg("Updating LUKS header of size %zu on device %s",
		sizeof(struct luks_phdr), device_path(device));

	r = LUKS_check_device_size(ctx, hdr->keyBytes);
	if (r)
		return r;

	devfd = device_open(device, O_RDWR);
	if(-1 == devfd) {
		if (errno == EACCES)
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
		else
			log_err(ctx, _("Cannot open device %s.\n"), device_path(device));
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

	r = write_blockwise(devfd, device_block_size(device), &convHdr, hdr_size) < hdr_size ? -EIO : 0;
	if (r)
		log_err(ctx, _("Error during update of LUKS header on device %s.\n"), device_path(device));
	close(devfd);

	/* Re-read header from disk to be sure that in-memory and on-disk data are the same. */
	if (!r) {
		r = LUKS_read_phdr(hdr, 1, 0, ctx);
		if (r)
			log_err(ctx, _("Error re-reading LUKS header after update on device %s.\n"),
				device_path(device));
	}

	return r;
}

/* Check that kernel supports requested cipher by decryption of one sector */
static int LUKS_check_cipher(struct luks_phdr *hdr, struct crypt_device *ctx)
{
	int r;
	struct volume_key *empty_key;
	char buf[SECTOR_SIZE];

	log_dbg("Checking if cipher %s-%s is usable.", hdr->cipherName, hdr->cipherMode);

	empty_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!empty_key)
		return -ENOMEM;

	r = LUKS_decrypt_from_storage(buf, sizeof(buf),
				      hdr->cipherName, hdr->cipherMode,
				      empty_key, 0, ctx);

	crypt_free_volume_key(empty_key);
	memset(buf, 0, sizeof(buf));
	return r;
}

int LUKS_generate_phdr(struct luks_phdr *header,
		       const struct volume_key *vk,
		       const char *cipherName, const char *cipherMode, const char *hashSpec,
		       const char *uuid, unsigned int stripes,
		       unsigned int alignPayload,
		       unsigned int alignOffset,
		       uint32_t iteration_time_ms,
		       uint64_t *PBKDF2_per_sec,
		       int detached_metadata_device,
		       struct crypt_device *ctx)
{
	unsigned int i = 0, hdr_sectors = LUKS_device_sectors(vk->keylength);
	size_t blocksPerStripeSet, currentSector;
	int r;
	uuid_t partitionUuid;
	char luksMagic[] = LUKS_MAGIC;

	/* For separate metadata device allow zero alignment */
	if (alignPayload == 0 && !detached_metadata_device)
		alignPayload = DEFAULT_DISK_ALIGNMENT / SECTOR_SIZE;

	if (alignPayload && detached_metadata_device && alignPayload < hdr_sectors) {
		log_err(ctx, _("Data offset for detached LUKS header must be "
			       "either 0 or higher than header size (%d sectors).\n"),
			       hdr_sectors);
		return -EINVAL;
	}

	if (crypt_hmac_size(hashSpec) < LUKS_DIGESTSIZE) {
		log_err(ctx, _("Requested LUKS hash %s is not supported.\n"), hashSpec);
		return -EINVAL;
	}

	if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
		log_err(ctx, _("Wrong LUKS UUID format provided.\n"));
		return -EINVAL;
	}
	if (!uuid)
		uuid_generate(partitionUuid);

	memset(header,0,sizeof(struct luks_phdr));

	/* Set Magic */
	memcpy(header->magic,luksMagic,LUKS_MAGIC_L);
	header->version=1;
	strncpy(header->cipherName,cipherName,LUKS_CIPHERNAME_L);
	strncpy(header->cipherMode,cipherMode,LUKS_CIPHERMODE_L);
	strncpy(header->hashSpec,hashSpec,LUKS_HASHSPEC_L);

	header->keyBytes=vk->keylength;

	LUKS_fix_header_compatible(header);

	r = LUKS_check_cipher(header, ctx);
	if (r < 0)
		return r;

	log_dbg("Generating LUKS header version %d using hash %s, %s, %s, MK %d bytes",
		header->version, header->hashSpec ,header->cipherName, header->cipherMode,
		header->keyBytes);

	r = crypt_random_get(ctx, header->mkDigestSalt, LUKS_SALTSIZE, CRYPT_RND_SALT);
	if(r < 0) {
		log_err(ctx, _("Cannot create LUKS header: reading random salt failed.\n"));
		return r;
	}

	r = crypt_benchmark_kdf(ctx, "pbkdf2", header->hashSpec,
				"foo", 3, "bar", 3, PBKDF2_per_sec);
	if (r < 0) {
		log_err(ctx, _("Not compatible PBKDF2 options (using hash algorithm %s).\n"),
			header->hashSpec);
		return r;
	}

	/* Compute master key digest */
	iteration_time_ms /= 8;
	header->mkDigestIterations = at_least((uint32_t)(*PBKDF2_per_sec/1024) * iteration_time_ms,
					      LUKS_MKD_ITERATIONS_MIN);

	r = crypt_pbkdf("pbkdf2", header->hashSpec, vk->key,vk->keylength,
			header->mkDigestSalt, LUKS_SALTSIZE,
			header->mkDigest,LUKS_DIGESTSIZE,
			header->mkDigestIterations);
	if(r < 0) {
		log_err(ctx, _("Cannot create LUKS header: header digest failed (using hash %s).\n"),
			header->hashSpec);
		return r;
	}

	currentSector = LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;
	blocksPerStripeSet = AF_split_sectors(vk->keylength, stripes);
	for(i = 0; i < LUKS_NUMKEYS; ++i) {
		header->keyblock[i].active = LUKS_KEY_DISABLED;
		header->keyblock[i].keyMaterialOffset = currentSector;
		header->keyblock[i].stripes = stripes;
		currentSector = size_round_up(currentSector + blocksPerStripeSet,
						LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
	}

	if (detached_metadata_device) {
		/* for separate metadata device use alignPayload directly */
		header->payloadOffset = alignPayload;
	} else {
		/* alignOffset - offset from natural device alignment provided by topology info */
		currentSector = size_round_up(currentSector, alignPayload);
		header->payloadOffset = currentSector + alignOffset;
	}

        uuid_unparse(partitionUuid, header->uuid);

	log_dbg("Data offset %d, UUID %s, digest iterations %" PRIu32,
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
		log_err(ctx, _("Wrong LUKS UUID format provided.\n"));
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
		 uint32_t iteration_time_ms,
		 uint64_t *PBKDF2_per_sec,
		 struct crypt_device *ctx)
{
	struct volume_key *derived_key;
	char *AfKey = NULL;
	size_t AFEKSize;
	uint64_t PBKDF2_temp;
	int r;

	if(hdr->keyblock[keyIndex].active != LUKS_KEY_DISABLED) {
		log_err(ctx, _("Key slot %d active, purge first.\n"), keyIndex);
		return -EINVAL;
	}

	/* LUKS keyslot has always at least 4000 stripes accoding to specification */
	if(hdr->keyblock[keyIndex].stripes < 4000) {
	        log_err(ctx, _("Key slot %d material includes too few stripes. Header manipulation?\n"),
			keyIndex);
	         return -EINVAL;
	}

	log_dbg("Calculating data for key slot %d", keyIndex);

	r = crypt_benchmark_kdf(ctx, "pbkdf2", hdr->hashSpec,
				"foo", 3, "bar", 3, PBKDF2_per_sec);
	if (r < 0) {
		log_err(ctx, _("Not compatible PBKDF2 options (using hash algorithm %s).\n"),
			hdr->hashSpec);
		return r;
	}

	/*
	 * Avoid floating point operation
	 * Final iteration count is at least LUKS_SLOT_ITERATIONS_MIN
	 */
	PBKDF2_temp = (*PBKDF2_per_sec / 2) * (uint64_t)iteration_time_ms;
	PBKDF2_temp /= 1024;
	if (PBKDF2_temp > UINT32_MAX)
		PBKDF2_temp = UINT32_MAX;
	hdr->keyblock[keyIndex].passwordIterations = at_least((uint32_t)PBKDF2_temp,
							      LUKS_SLOT_ITERATIONS_MIN);

	log_dbg("Key slot %d use %d password iterations.", keyIndex, hdr->keyblock[keyIndex].passwordIterations);

	derived_key = crypt_alloc_volume_key(hdr->keyBytes, NULL);
	if (!derived_key)
		return -ENOMEM;

	r = crypt_random_get(ctx, hdr->keyblock[keyIndex].passwordSalt,
		       LUKS_SALTSIZE, CRYPT_RND_SALT);
	if (r < 0)
		goto out;

	r = crypt_pbkdf("pbkdf2", hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, LUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations);
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

	log_dbg("Using hash %s for AF in key slot %d, %d stripes",
		hdr->hashSpec, keyIndex, hdr->keyblock[keyIndex].stripes);
	r = AF_split(vk->key,AfKey,vk->keylength,hdr->keyblock[keyIndex].stripes,hdr->hashSpec);
	if (r < 0)
		goto out;

	log_dbg("Updating key slot %d [0x%04x] area.", keyIndex,
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
	r = LUKS_keyslot_set(hdr, (int)keyIndex, 1);
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

	if (crypt_pbkdf("pbkdf2", hdr->hashSpec, vk->key, vk->keylength,
			hdr->mkDigestSalt, LUKS_SALTSIZE,
			checkHashBuf, LUKS_DIGESTSIZE,
			hdr->mkDigestIterations) < 0)
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

	log_dbg("Trying to open key slot %d [%s].", keyIndex,
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

	r = crypt_pbkdf("pbkdf2", hdr->hashSpec, password, passwordLen,
			hdr->keyblock[keyIndex].passwordSalt, LUKS_SALTSIZE,
			derived_key->key, hdr->keyBytes,
			hdr->keyblock[keyIndex].passwordIterations);
	if (r < 0)
		goto out;

	log_dbg("Reading key slot %d area.", keyIndex);
	r = LUKS_decrypt_from_storage(AfKey,
				      AFEKSize,
				      hdr->cipherName, hdr->cipherMode,
				      derived_key,
				      hdr->keyblock[keyIndex].keyMaterialOffset,
				      ctx);
	if (r < 0)
		goto out;

	r = AF_merge(AfKey,vk->key,vk->keylength,hdr->keyblock[keyIndex].stripes,hdr->hashSpec);
	if (r < 0)
		goto out;

	r = LUKS_verify_volume_key(hdr, vk);
	if (!r)
		log_verbose(ctx, _("Key slot %d unlocked.\n"), keyIndex);
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
	unsigned int i;
	int r;

	*vk = crypt_alloc_volume_key(hdr->keyBytes, NULL);

	if (keyIndex >= 0) {
		r = LUKS_open_key(keyIndex, password, passwordLen, hdr, *vk, ctx);
		return (r < 0) ? r : keyIndex;
	}

	for(i = 0; i < LUKS_NUMKEYS; i++) {
		r = LUKS_open_key(i, password, passwordLen, hdr, *vk, ctx);
		if(r == 0)
			return i;

		/* Do not retry for errors that are no -EPERM or -ENOENT,
		   former meaning password wrong, latter key slot inactive */
		if ((r != -EPERM) && (r != -ENOENT))
			return r;
	}
	/* Warning, early returns above */
	log_err(ctx, _("No key available with this passphrase.\n"));
	return -EPERM;
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

	r = LUKS_keyslot_set(hdr, keyIndex, 0);
	if (r) {
		log_err(ctx, _("Key slot %d is invalid, please select keyslot between 0 and %d.\n"),
			keyIndex, LUKS_NUMKEYS - 1);
		return r;
	}

	/* secure deletion of key material */
	startOffset = hdr->keyblock[keyIndex].keyMaterialOffset;
	endOffset = startOffset + AF_split_sectors(hdr->keyBytes, hdr->keyblock[keyIndex].stripes);

	r = crypt_wipe(device, startOffset * SECTOR_SIZE,
		       (endOffset - startOffset) * SECTOR_SIZE,
		       CRYPT_WIPE_DISK, 0);
	if (r) {
		if (r == -EACCES) {
			log_err(ctx, _("Cannot write to device %s, permission denied.\n"),
				device_path(device));
			r = -EINVAL;
		} else
			log_err(ctx, _("Cannot wipe device %s.\n"),
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

int LUKS_keyslot_set(struct luks_phdr *hdr, int keyslot, int enable)
{
	crypt_keyslot_info ki = LUKS_keyslot_info(hdr, keyslot);

	if (ki == CRYPT_SLOT_INVALID)
		return -EINVAL;

	hdr->keyblock[keyslot].active = enable ? LUKS_KEY_ENABLED : LUKS_KEY_DISABLED;
	log_dbg("Key slot %d was %s in LUKS header.", keyslot, enable ? "enabled" : "disabled");
	return 0;
}

int LUKS1_activate(struct crypt_device *cd,
		   const char *name,
		   struct volume_key *vk,
		   uint32_t flags)
{
	int r;
	char *dm_cipher = NULL;
	enum devcheck device_check;
	struct crypt_dm_active_device dmd = {
		.target = DM_CRYPT,
		.uuid   = crypt_get_uuid(cd),
		.flags  = flags,
		.size   = 0,
		.data_device = crypt_data_device(cd),
		.u.crypt = {
			.cipher = NULL,
			.vk     = vk,
			.offset = crypt_get_data_offset(cd),
			.iv_offset = 0,
		}
	};

	if (dmd.flags & CRYPT_ACTIVATE_SHARED)
		device_check = DEV_SHARED;
	else
		device_check = DEV_EXCL;

	r = device_block_adjust(cd, dmd.data_device, device_check,
				 dmd.u.crypt.offset, &dmd.size, &dmd.flags);
	if (r)
		return r;

	r = asprintf(&dm_cipher, "%s-%s", crypt_get_cipher(cd), crypt_get_cipher_mode(cd));
	if (r < 0)
		return -ENOMEM;

	dmd.u.crypt.cipher = dm_cipher;
	r = dm_create_device(cd, name, CRYPT_LUKS1, &dmd, 0);

	free(dm_cipher);
	return r;
}
