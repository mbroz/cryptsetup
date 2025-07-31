// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * utils_wipe - wipe a device
 *
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>
#include "internal.h"
#include "luks2/luks2_internal.h"
#include "luks2/hw_opal/hw_opal.h"

/* block device zeroout ioctls, introduced in Linux kernel 3.7 */
#ifndef BLKZEROOUT
#define BLKZEROOUT _IO(0x12,127)
#endif

static int wipe_zeroout(struct crypt_device *cd, int devfd,
			uint64_t offset, uint64_t length)
{
	static bool zeroout_available = true;
	uint64_t range[2] = { offset, length };
	int r;

	if (!zeroout_available)
		return -ENOTSUP;

	r = ioctl(devfd, BLKZEROOUT, &range);
	if (r < 0) {
		log_dbg(cd, "BLKZEROOUT ioctl not available (error %i), disabling.", r);
		zeroout_available = false;
		return -ENOTSUP;
	}

	return 0;
}

/*
 * Wipe using Peter Gutmann method described in
 * https://www.cs.auckland.ac.nz/~pgut001/pubs/secure_del.html
 * Note: used only for rotational device (and even there it is not needed today...)
 */
static void wipeSpecial(char *buffer, size_t buffer_size, unsigned int turn)
{
	unsigned int i;

	const unsigned char write_modes[27][4] = {
		{"\x55\x55\x55"}, {"\xaa\xaa\xaa"}, {"\x92\x49\x24"},
		{"\x49\x24\x92"}, {"\x24\x92\x49"}, {"\x00\x00\x00"},
		{"\x11\x11\x11"}, {"\x22\x22\x22"}, {"\x33\x33\x33"},
		{"\x44\x44\x44"}, {"\x55\x55\x55"}, {"\x66\x66\x66"},
		{"\x77\x77\x77"}, {"\x88\x88\x88"}, {"\x99\x99\x99"},
		{"\xaa\xaa\xaa"}, {"\xbb\xbb\xbb"}, {"\xcc\xcc\xcc"},
		{"\xdd\xdd\xdd"}, {"\xee\xee\xee"}, {"\xff\xff\xff"},
		{"\x92\x49\x24"}, {"\x49\x24\x92"}, {"\x24\x92\x49"},
		{"\x6d\xb6\xdb"}, {"\xb6\xdb\x6d"}, {"\xdb\x6d\xb6"}
	};

	for (i = 0; i < buffer_size / 3; ++i) {
		memcpy(buffer, write_modes[turn], 3);
		buffer += 3;
	}
}

static int crypt_wipe_special(struct crypt_device *cd, int fd, size_t bsize,
			      size_t alignment, char *buffer,
			      uint64_t offset, size_t size)
{
	int r = 0;
	unsigned int i;
	ssize_t written;

	for (i = 0; i < 39; ++i) {
		if (i <  5) {
			r = crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL);
		} else if (i >=  5 && i < 32) {
			wipeSpecial(buffer, size, i - 5);
			r = 0;
		} else if (i >= 32 && i < 38) {
			r = crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL);
		} else if (i >= 38 && i < 39) {
			memset(buffer, 0xFF, size);
			r = 0;
		}
		if (r < 0)
			return -EIO;

		written = write_lseek_blockwise(fd, bsize, alignment,
						buffer, size, offset);
		if (written < 0 || written != (ssize_t)size)
			return -EIO;
	}

	/* Rewrite it finally with random */
	if (crypt_random_get(cd, buffer, size, CRYPT_RND_NORMAL) < 0)
		return -EIO;

	written = write_lseek_blockwise(fd, bsize, alignment, buffer, size, offset);
	if (written < 0 || written != (ssize_t)size)
		return -EIO;

	return 0;
}

static int wipe_block(struct crypt_device *cd, int devfd, crypt_wipe_pattern pattern,
		      char *sf, size_t device_block_size, size_t alignment,
		      size_t wipe_block_size, uint64_t offset, bool *need_block_init,
		      bool blockdev)
{
	int r;

	if (pattern == CRYPT_WIPE_SPECIAL)
		return crypt_wipe_special(cd, devfd, device_block_size, alignment,
					  sf, offset, wipe_block_size);

	if (*need_block_init) {
		if (pattern == CRYPT_WIPE_ZERO) {
			memset(sf, 0, wipe_block_size);
			*need_block_init = false;
			r = 0;
		} else if (pattern == CRYPT_WIPE_RANDOM ||
			   pattern == CRYPT_WIPE_ENCRYPTED_ZERO) {
			r = crypt_random_get(cd, sf, wipe_block_size,
					     CRYPT_RND_NORMAL) ? -EIO : 0;
			*need_block_init = true;
		} else
			r = -EINVAL;

		if (r)
			return r;
	}

	if (blockdev && pattern == CRYPT_WIPE_ZERO &&
	    !wipe_zeroout(cd, devfd, offset, wipe_block_size)) {
		/* zeroout ioctl does not move offset */
		if (lseek(devfd, offset + wipe_block_size, SEEK_SET) < 0) {
			log_err(cd, _("Cannot seek to device offset."));
			return -EINVAL;
		}
		return 0;
	}

	if (write_blockwise(devfd, device_block_size, alignment, sf,
			    wipe_block_size) == (ssize_t)wipe_block_size)
		return 0;

	return -EIO;
}

int crypt_wipe_device(struct crypt_device *cd,
	struct device *device,
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	int r, devfd;
	struct stat st;
	size_t bsize, alignment;
	char *sf = NULL;
	uint64_t dev_size;
	bool need_block_init = true;

	/* Note: LUKS1 calls it with wipe_block not aligned to multiple of bsize */
	bsize = device_block_size(cd, device);
	alignment = device_alignment(device);

	log_dbg(cd, "Wipe device %s [%u], offset %" PRIu64 ", length %" PRIu64 ", block %zu, bsize %zu, align %zu.",
		device_path(device), (unsigned)pattern, offset, length, wipe_block_size, bsize, alignment);

	if (!bsize || !alignment || !wipe_block_size)
		return -EINVAL;

	/* if wipe_block_size < bsize, then a wipe is highly ineffective */

	/* Everything must be aligned to SECTOR_SIZE */
	if (MISALIGNED_512(offset) || MISALIGNED_512(length) || MISALIGNED_512(wipe_block_size))
		return -EINVAL;

	if (device_is_locked(device))
		devfd = device_open_locked(cd, device, O_RDWR);
	else
		devfd = device_open(cd, device, O_RDWR);
	if (devfd < 0)
		return errno ? -errno : -EINVAL;

	if (fstat(devfd, &st) < 0) {
		r = -EINVAL;
		goto out;
	}

	if (length)
		dev_size = offset + length;
	else {
		r = device_size(device, &dev_size);
		if (r)
			goto out;

		if (dev_size <= offset) {
			r = -EINVAL;
			goto out;
		}
	}

	r = posix_memalign((void **)&sf, alignment, wipe_block_size);
	if (r)
		goto out;

	if (lseek(devfd, offset, SEEK_SET) < 0) {
		log_err(cd, _("Cannot seek to device offset."));
		r = -EINVAL;
		goto out;
	}

	if (progress && progress(dev_size, offset, usrptr)) {
		r = -EINVAL; /* No change yet, treat this as a parameter error */
		goto out;
	}

	if (pattern == CRYPT_WIPE_SPECIAL && !device_is_rotational(device)) {
		log_dbg(cd, "Non-rotational device, using random data wipe mode.");
		pattern = CRYPT_WIPE_RANDOM;
	}

	while (offset < dev_size) {
		if ((offset + wipe_block_size) > dev_size)
			wipe_block_size = dev_size - offset;

		r = wipe_block(cd, devfd, pattern, sf, bsize, alignment,
			       wipe_block_size, offset, &need_block_init, S_ISBLK(st.st_mode));
		if (r) {
			log_err(cd,_("Device wipe error, offset %" PRIu64 "."), offset);
			break;
		}

		offset += wipe_block_size;

		if (progress && progress(dev_size, offset, usrptr)) {
			r = -EINTR;
			break;
		}
	}

	device_sync(cd, device);
out:
	free(sf);
	return r;
}

int crypt_wipe(struct crypt_device *cd,
	const char *dev_path,
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	uint32_t flags,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr)
{
	struct device *device;
	int r;

	if (!cd)
		return -EINVAL;

	r = init_crypto(cd);
	if (r < 0)
		return r;

	if (!dev_path)
		device = crypt_data_device(cd);
	else {
		r = device_alloc_no_check(&device, dev_path);
		if (r < 0)
			return r;

		if (flags & CRYPT_WIPE_NO_DIRECT_IO)
			device_disable_direct_io(device);
	}
	if (!device)
		return -EINVAL;

	if (!wipe_block_size)
		wipe_block_size = 1024*1024;

	r = crypt_wipe_device(cd, device, pattern, offset, length,
			      wipe_block_size, progress, usrptr);

	if (dev_path)
		device_free(cd, device);

	return r;
}

int crypt_wipe_hw_opal(struct crypt_device *cd,
		       int segment,
		       const char *password,
		       size_t password_size,
		       uint32_t flags)
{
	int r;
	struct luks2_hdr *hdr;
	uint32_t opal_segment_number;
	struct crypt_lock_handle *opal_lh = NULL;

	UNUSED(flags);

	if (!cd)
		return -EINVAL;

	if (!password)
		return -EINVAL;

	if (segment < CRYPT_LUKS2_SEGMENT || segment > 8)
		return -EINVAL;

	r = crypt_opal_supported(cd, crypt_data_device(cd));
	if (r < 0)
		return r;

	if (segment == CRYPT_NO_SEGMENT) {
		r = opal_factory_reset(cd, crypt_data_device(cd), password, password_size);
		if (r == -EPERM)
			log_err(cd, _("Incorrect OPAL PSID."));
		else if (r < 0)
			log_err(cd, _("Cannot erase OPAL device."));
		return r;
	}

	if (onlyLUKS2(cd) < 0)
		return -EINVAL;

	hdr = crypt_get_hdr(cd, CRYPT_LUKS2);
	if (!hdr)
		return -EINVAL;

	if (segment == CRYPT_LUKS2_SEGMENT) {
		r = LUKS2_get_opal_segment_number(hdr, CRYPT_DEFAULT_SEGMENT, &opal_segment_number);
		if (r < 0) {
			log_dbg(cd, "Can not get OPAL segment number.");
			return r;
		}
	} else
		opal_segment_number = segment;

	r = opal_exclusive_lock(cd, crypt_data_device(cd), &opal_lh);
	if (r < 0) {
		log_err(cd, _("Failed to acquire OPAL lock on device %s."), device_path(crypt_data_device(cd)));
		return -EINVAL;
	}

	r = opal_reset_segment(cd,
			       crypt_data_device(cd),
			       opal_segment_number,
			       password,
			       password_size);

	opal_exclusive_unlock(cd, opal_lh);
	if (r < 0)
		return r;

	return LUKS2_wipe_header_areas(cd, hdr);
}
