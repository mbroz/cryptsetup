/*
 * cryptsetup library API check functions
 *
 * Copyright (C) 2009-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2020 Milan Broz
 * Copyright (C) 2016-2020 Ondrej Kozina
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

int fips_mode(void);

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

#define SECTOR_SHIFT 9L
#define SECTOR_SIZE 512
#define TST_LOOP_FILE_SIZE (((1<<20)*100)>>SECTOR_SHIFT)
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_MODULO(n,d) (DIV_ROUND_UP(n,d)*(d))

/* Device mapper backend - kernel support flags */
#define T_DM_KEY_WIPE_SUPPORTED (1 << 0)	/* key wipe message */
#define T_DM_LMK_SUPPORTED      (1 << 1)	/* lmk mode */
#define T_DM_SECURE_SUPPORTED   (1 << 2)	/* wipe (secure) buffer flag */
#define T_DM_PLAIN64_SUPPORTED  (1 << 3)	/* plain64 IV */
#define T_DM_DISCARDS_SUPPORTED (1 << 4)	/* discards/TRIM option is supported */
#define T_DM_VERITY_SUPPORTED   (1 << 5)	/* dm-verity target supported */
#define T_DM_TCW_SUPPORTED      (1 << 6)	/* tcw (TCRYPT CBC with whitening) */
#define T_DM_SAME_CPU_CRYPT_SUPPORTED (1 << 7) /* same_cpu_crypt */
#define T_DM_SUBMIT_FROM_CRYPT_CPUS_SUPPORTED (1 << 8) /* submit_from_crypt_cpus */
#define T_DM_VERITY_ON_CORRUPTION_SUPPORTED (1 << 9) /* ignore/restart_on_corruption, ignore_zero_block */
#define T_DM_VERITY_FEC_SUPPORTED (1 << 10) /* Forward Error Correction (FEC) */
#define T_DM_KERNEL_KEYRING_SUPPORTED (1 << 11) /* dm-crypt allows loading kernel keyring keys */
#define T_DM_INTEGRITY_SUPPORTED (1 << 12) /* dm-integrity target supported */
//FIXME add T_DM_SECTOR_SIZE once we have version

/* loop helpers */
int loop_device(const char *loop);
int loop_attach(char **loop, const char *file, int offset,
		      int autoclear, int *readonly);
int loop_detach(const char *loop);

#endif
