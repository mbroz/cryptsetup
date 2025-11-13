// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup library API check functions
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 * Copyright (C) 2016-2025 Ondrej Kozina
 */

#ifndef API_TEST_H
#define API_TEST_H

#include <stdio.h>
#include <stdint.h>

extern char *THE_LOOP_DEV;
extern int _debug;
extern int global_lines;
extern int _quit;
extern int _verbose;
extern uint64_t t_dev_offset;

int t_device_size(const char *device, uint64_t *size);
int t_dm_check_versions(void);
int t_dm_crypt_keyring_support(void);
int t_dm_crypt_cpu_switch_support(void);
int t_dm_crypt_discard_support(void);
int t_dm_integrity_resize_support(void);
int t_dm_integrity_recalculate_support(void);
int t_dm_capi_string_supported(void);
int t_set_readahead(const char *device, unsigned value);

int fips_mode(void);
int fips_mode_kernel(void);

int create_dmdevice_over_device(const char *dm_name, const char *device, uint64_t size, uint64_t offset);

int create_dmdevice_over_loop(const char *dm_name, const uint64_t size);

int get_key_dm(const char *name, char *buffer, unsigned int buffer_size);

int prepare_keyfile(const char *name, const char *passphrase, int size);

int crypt_decode_key(char *key, const char *hex, unsigned int size);

void global_log_callback(int level, const char *msg, void *usrptr);

void reset_log(void);

int _system(const char *command, int warn);

void register_cleanup(void (*cleanup)(void));

void check_ok(int status, int line, const char *func);
void check_ok_return(int status, int line, const char *func);
void check_ko(int status, int line, const char *func);
void check_equal(int line, const char *func, int64_t x, int64_t y);
void check_ge_equal(int line, const char *func, int64_t x, int64_t y);
void check_null(int line, const char *func, const void *x);
void check_notnull(int line, const char *func, const void *x);
void xlog(const char *msg, const char *tst, const char *func, int line, const char *txt);

/* crypt_device context must be "cd" to parse error properly here */
#define OK_(x)		do { xlog("(success)", #x, __FUNCTION__, __LINE__, NULL); \
			     check_ok((x), __LINE__, __FUNCTION__); \
			} while(0)
#define NOTFAIL_(x, y)	do { xlog("(notfail)", #x, __FUNCTION__, __LINE__, y); \
			     check_ok_return((x), __LINE__, __FUNCTION__); \
			} while(0)
#define FAIL_(x, y)	do { xlog("(fail)   ", #x, __FUNCTION__, __LINE__, y); \
			     check_ko((x), __LINE__, __FUNCTION__); \
			} while(0)
#define EQ_(x, y)	do { int64_t _x = (x), _y = (y); \
			     xlog("(equal)  ", #x " == " #y, __FUNCTION__, __LINE__, NULL); \
			     if (_x != _y) check_equal(__LINE__, __FUNCTION__, _x, _y); \
			} while(0)
#define GE_(x, y)	do { int64_t _x = (x), _y = (y); \
			     xlog("(g_equal)", #x " == " #y, __FUNCTION__, __LINE__, NULL); \
			     if (_x < _y) check_ge_equal(__LINE__, __FUNCTION__, _x, _y); \
			} while(0)
#define NULL_(x)	do { xlog("(null)   ", #x, __FUNCTION__, __LINE__, NULL); \
			     check_null(__LINE__, __FUNCTION__, (x)); \
			} while(0)
#define NOTNULL_(x)	do { xlog("(notnull)", #x, __FUNCTION__, __LINE__, NULL); \
			     check_notnull(__LINE__, __FUNCTION__, (x)); \
			} while(0)
#define RUN_(x, y)	do { reset_log(); \
			     printf("%s: %s\n", #x, (y)); x(); \
			} while (0)

#define CRYPT_FREE(x) do { crypt_free(x); x = NULL; } while (0)

/* to silent clang -Wcast-align when working with byte arrays */
#define VOIDP_CAST(x) (x)(void*)

#define DMDIR "/dev/mapper/"

#define TST_SECTOR_SHIFT 9L
#define TST_SECTOR_SIZE 512
#define TST_LOOP_FILE_SIZE (((1 << 20) * 100) >> TST_SECTOR_SHIFT)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_MODULO(n,d) (DIV_ROUND_UP(n,d)*(d))

/* Device mapper backend - kernel support flags */
#define T_DM_KEY_WIPE_SUPPORTED (UINT64_C(1) << 0)	/* key wipe message */
#define T_DM_LMK_SUPPORTED      (UINT64_C(1) << 1)	/* lmk mode */
#define T_DM_SECURE_SUPPORTED   (UINT64_C(1) << 2)	/* wipe (secure) buffer flag */
#define T_DM_PLAIN64_SUPPORTED  (UINT64_C(1) << 3)	/* plain64 IV */
#define T_DM_DISCARDS_SUPPORTED (UINT64_C(1) << 4)	/* discards/TRIM option is supported */
#define T_DM_VERITY_SUPPORTED   (UINT64_C(1) << 5)	/* dm-verity target supported */
#define T_DM_TCW_SUPPORTED      (UINT64_C(1) << 6)	/* tcw (TCRYPT CBC with whitening) */
#define T_DM_SAME_CPU_CRYPT_SUPPORTED (UINT64_C(1) << 7) /* same_cpu_crypt */
#define T_DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED (UINT64_C(1) << 8) /* submit_from_crypt_cpus */
#define T_DM_VERITY_ON_CORRUPTION_SUPPORTED (UINT64_C(1) << 9) /* ignore/restart_on_corruption, ignore_zero_block */
#define T_DM_VERITY_FEC_SUPPORTED (UINT64_C(1) << 10) /* Forward Error Correction (FEC) */
#define T_DM_KERNEL_KEYRING_SUPPORTED (UINT64_C(1) << 11) /* dm-crypt allows loading kernel keyring keys */
#define T_DM_INTEGRITY_SUPPORTED (UINT64_C(1) << 12) /* dm-integrity target supported */
#define T_DM_SECTOR_SIZE_SUPPORTED (UINT64_C(1) << 13) /* support for sector size setting in dm-crypt/dm-integrity */
#define T_DM_CAPI_STRING_SUPPORTED (UINT64_C(1) << 14) /* support for cryptoapi format cipher definition */
#define T_DM_DEFERRED_SUPPORTED (UINT64_C(1) << 15) /* deferred removal of device */
#define T_DM_INTEGRITY_RECALC_SUPPORTED (UINT64_C(1) << 16) /* dm-integrity automatic recalculation supported */
#define T_DM_INTEGRITY_BITMAP_SUPPORTED (UINT64_C(1) << 17) /* dm-integrity bitmap mode supported */
#define T_DM_GET_TARGET_VERSION_SUPPORTED (UINT64_C(1) << 18) /* dm DM_GET_TARGET version ioctl supported */
#define T_DM_INTEGRITY_FIX_PADDING_SUPPORTED (UINT64_C(1) << 19) /* supports the parameter fix_padding that fixes a bug that caused excessive padding */
#define T_DM_BITLK_EBOIV_SUPPORTED (UINT64_C(1) << 20) /* EBOIV for BITLK supported */
#define T_DM_BITLK_ELEPHANT_SUPPORTED (UINT64_C(1) << 21) /* Elephant diffuser for BITLK supported */
#define T_DM_VERITY_SIGNATURE_SUPPORTED (UINT64_C(1) << 22) /* Verity option root_hash_sig_key_desc supported */
#define T_DM_INTEGRITY_DISCARDS_SUPPORTED (UINT64_C(1) << 23) /* dm-integrity discards/TRIM option is supported */
#define T_DM_INTEGRITY_RESIZE_SUPPORTED (UINT64_C(1) << 23) /* dm-integrity resize of the integrity device supported (introduced in the same version as discards)*/
#define T_DM_VERITY_PANIC_CORRUPTION_SUPPORTED (UINT64_C(1) << 24) /* dm-verity panic on corruption  */
#define T_DM_CRYPT_NO_WORKQUEUE_SUPPORTED (UINT64_C(1) << 25) /* dm-crypt support for bypassing workqueues  */
#define T_DM_INTEGRITY_FIX_HMAC_SUPPORTED (UINT64_C(1) << 26) /* hmac covers also superblock */
#define T_DM_INTEGRITY_RESET_RECALC_SUPPORTED (UINT64_C(1) << 27) /* dm-integrity automatic recalculation supported */
#define T_DM_VERITY_TASKLETS_SUPPORTED (UINT64_C(1) << 28) /* dm-verity tasklets supported */
#define T_DM_CRYPT_HIGH_PRIORITY_SUPPORTED (UINT64_C(1) << 29) /* dm-crypt high priority workqueue flag supported  */
#define T_DM_CRYPT_INTEGRITY_KEY_SIZE_OPT_SUPPORTED (UINT64_C(1) << 30) /* dm-crypt support for integrity_key_size option */
#define T_DM_VERITY_ERROR_AS_CORRUPTION_SUPPORTED (UINT64_C(1) << 31) /* dm-verity restart/panic on corruption supported */
#define T_DM_INTEGRITY_INLINE_MODE_SUPPORTED (UINT64_C(1) << 32) /* dm-integrity inline mode supported */

/* loop helpers */
int loop_device(const char *loop);
int loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly);
int loop_detach(const char *loop);

int t_device_size_by_devno(dev_t devno, uint64_t *retval);
int t_get_devno(const char *dev, dev_t *devno);

typedef enum { ERR_RD = 0, ERR_WR, ERR_RW, ERR_REMOVE } error_io_info;

int dmdevice_error_io(const char *dm_name,
	const char *dm_device,
	const char *error_device,
	uint64_t data_offset,
	uint64_t offset,
	uint64_t length,
	error_io_info ei);

#endif
