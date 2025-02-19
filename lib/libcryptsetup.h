/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * libcryptsetup - cryptsetup library
 *
 * Copyright (C) 2004 Jana Saout <jana@saout.de>
 * Copyright (C) 2004-2007 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

/**
 * @file libcryptsetup.h
 * @brief Public cryptsetup API
 *
 * For more verbose examples of LUKS related use cases,
 * please read @ref index "examples".
 */

#ifndef _LIBCRYPTSETUP_H
#define _LIBCRYPTSETUP_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/**
 * @defgroup crypt-init Cryptsetup device context initialization
 * Set of functions for creating and destroying @e crypt_device context
 * @addtogroup crypt-init
 * @{
 */

struct crypt_device; /* crypt device handle */
struct crypt_keyslot_context;

/**
 * Initialize crypt device handle and check if the provided device exists.
 *
 * @param cd Returns pointer to crypt device handle
 * @param device Path to the backing device.
 * 	  If @e device is not a block device but a path to some file,
 * 	  the function will try to create a loopdevice and attach
 * 	  the file to the loopdevice with AUTOCLEAR flag set.
 * 	  If @e device is @e NULL function it will initialize dm backend only.
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note Note that logging is not initialized here, possible messages use
 * 	 default log function.
 */
int crypt_init(struct crypt_device **cd, const char *device);

/**
 * Initialize crypt device handle with optional data device and check
 * if devices exist.
 *
 * @param cd Returns pointer to crypt device handle
 * @param device Path to the backing device or detached header.
 * @param data_device Path to the data device or @e NULL.
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note Note that logging is not initialized here, possible messages use
 * 	 default log function.
 */
int crypt_init_data_device(struct crypt_device **cd,
	const char *device,
	const char *data_device);

/**
 * Initialize crypt device handle from provided active device name,
 * and, optionally, from separate metadata (header) device
 * and check if provided device exists.
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @param cd returns crypt device handle for active device
 * @param name name of active crypt device
 * @param header_device optional device containing on-disk header
 * 	  (@e NULL if it the same as underlying device on there is no on-disk header)
 *
 * @post In case @e device points to active LUKS device but header load fails,
 * context device type is set to @e NULL and @e 0 is returned as if it were successful.
 * Context with @e NULL device type can only be deactivated by crypt_deactivate
 *
 * @note @link crypt_init_by_name @endlink is equivalent to calling
 * 	 crypt_init_by_name_and_header(cd, name, NULL);
 */
int crypt_init_by_name_and_header(struct crypt_device **cd,
	const char *name,
	const char *header_device);

/**
 * This is equivalent to call
 * @ref crypt_init_by_name_and_header "crypt_init_by_name_and_header(cd, name, NULL)"
 *
 * @sa crypt_init_by_name_and_header
 */
int crypt_init_by_name(struct crypt_device **cd, const char *name);

/**
 * Release crypt device context and used memory.
 *
 * @param cd crypt device handle
 */
void crypt_free(struct crypt_device *cd);

/**
 * Set confirmation callback (yes/no).
 *
 * If code need confirmation (like resetting uuid or restoring LUKS header from file)
 * this function is called. If not defined, everything is confirmed.
 *
 * Callback function @e confirm should return @e 0 if operation is declined,
 * other values mean accepted.
 *
 * @param cd crypt device handle
 * @param confirm user defined confirm callback reference; use
 *        @p msg for message for user to confirm and
 *        @p usrptr for identification in callback
 * @param usrptr provided identification in callback
 *
 * @note Current version of cryptsetup API requires confirmation for UUID change and
 *	 LUKS header restore only.
 */
void crypt_set_confirm_callback(struct crypt_device *cd,
	int (*confirm)(const char *msg, void *usrptr),
	void *usrptr);

/**
 * Set data device
 * For LUKS it is encrypted data device when LUKS header is separated.
 * For VERITY it is data device when hash device is separated.
 *
 * @param cd crypt device handle
 * @param device path to device
 *
 * @returns 0 on success or negative errno value otherwise.
 */
int crypt_set_data_device(struct crypt_device *cd, const char *device);

/**
 * Set data device offset in 512-byte sectors.
 * Used for LUKS.
 * This function is replacement for data alignment fields in LUKS param struct.
 * If set to 0 (default), old behaviour is preserved.
 * This value is reset on @link crypt_load @endlink.
 *
 * @param cd crypt device handle
 * @param data_offset data offset in bytes
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @note Data offset must be aligned to multiple of 8 (alignment to 4096-byte sectors)
 * and must be big enough to accommodate the whole LUKS header with all keyslots.
 * @note Data offset is enforced by this function, device topology
 * information is no longer used after calling this function.
 */
int crypt_set_data_offset(struct crypt_device *cd, uint64_t data_offset);

/** @} */

/**
 * @defgroup crypt-log Cryptsetup logging
 * Set of functions and defines used in cryptsetup for
 * logging purposes
 * @addtogroup crypt-log
 * @{
 */

/** normal log level */
#define CRYPT_LOG_NORMAL 0
/** error log level */
#define CRYPT_LOG_ERROR  1
/** verbose log level */
#define CRYPT_LOG_VERBOSE  2
/** debug log level - always on stdout */
#define CRYPT_LOG_DEBUG -1
/** debug log level - additional JSON output (for LUKS2) */
#define CRYPT_LOG_DEBUG_JSON -2

/**
 * Set log function.
 *
 * @param cd crypt device handle (can be @e NULL to set default log function)
 * @param log user defined log function reference; use
 *        @p level for log level,
 *        @p msg for message, and
 *        @p usrptr for identification in callback
 * @param usrptr provided identification in callback
 */
void crypt_set_log_callback(struct crypt_device *cd,
	void (*log)(int level, const char *msg, void *usrptr),
	void *usrptr);

/**
 * Defines log function or use the default one otherwise.
 *
 * @see crypt_set_log_callback
 *
 * @param cd crypt device handle
 * @param level log level
 * @param msg log message
 */
void crypt_log(struct crypt_device *cd, int level, const char *msg);

/**
 * Log function with variable arguments.
 *
 * @param cd crypt device handle
 * @param level log level
 * @param format formatted log message
 */
void crypt_logf(struct crypt_device *cd, int level, const char *format, ...);
/** @} */

/**
 * @defgroup crypt-set Cryptsetup settings (RNG, PBKDF, locking)
 * @addtogroup crypt-set
 * @{
 */

/** CRYPT_RNG_URANDOM - use /dev/urandom */
#define CRYPT_RNG_URANDOM 0
/** CRYPT_RNG_RANDOM  - use /dev/random (waits if no entropy in system) */
#define CRYPT_RNG_RANDOM  1

/**
 * Set which RNG (random number generator) is used for generating long term key
 *
 * @param cd crypt device handle
 * @param rng_type kernel random number generator to use
 *
 */
void crypt_set_rng_type(struct crypt_device *cd, int rng_type);

/**
 * Get which RNG (random number generator) is used for generating long term key.
 *
 * @param cd crypt device handle
 * @return RNG type on success or negative errno value otherwise.
 *
 */
int crypt_get_rng_type(struct crypt_device *cd);

/**
 * PBKDF parameters.
 */
struct crypt_pbkdf_type {
	const char *type;         /**< PBKDF algorithm  */
	const char *hash;         /**< Hash algorithm */
	uint32_t time_ms;         /**< Requested time cost [milliseconds] */
	uint32_t iterations;      /**< Iterations, 0 or benchmarked value. */
	uint32_t max_memory_kb;   /**< Requested or benchmarked  memory cost [kilobytes] */
	uint32_t parallel_threads;/**< Requested parallel cost [threads] */
	uint32_t flags;           /**< CRYPT_PBKDF* flags */
};

/** Iteration time set by crypt_set_iteration_time(), for compatibility only. */
#define CRYPT_PBKDF_ITER_TIME_SET   (UINT32_C(1) << 0)
/** Never run benchmarks or limit by system resources, use pre-set values or defaults. */
#define CRYPT_PBKDF_NO_BENCHMARK    (UINT32_C(1) << 1)

/** PBKDF2 according to RFC2898, LUKS1 legacy */
#define CRYPT_KDF_PBKDF2   "pbkdf2"
/** Argon2i according to RFC */
#define CRYPT_KDF_ARGON2I  "argon2i"
/** Argon2id according to RFC */
#define CRYPT_KDF_ARGON2ID "argon2id"

/**
 * Set default PBKDF (Password-Based Key Derivation Algorithm) for next keyslot
 * about to get created with any crypt_keyslot_add_*() call.
 *
 * @param cd crypt device handle
 * @param pbkdf PBKDF parameters
 *
 * @return 0 on success or negative errno value otherwise.
 *
 * @note For LUKS1, only PBKDF2 is supported, other settings will be rejected.
 * @note For non-LUKS context types the call succeeds, but PBKDF is not used.
 */
int crypt_set_pbkdf_type(struct crypt_device *cd,
	 const struct crypt_pbkdf_type *pbkdf);

/**
 * Get PBKDF (Password-Based Key Derivation Algorithm) parameters.
 *
 * @param pbkdf_type type of PBKDF
 *
 * @return struct on success or NULL value otherwise.
 *
 */
const struct crypt_pbkdf_type *crypt_get_pbkdf_type_params(const char *pbkdf_type);

/**
 * Get default PBKDF (Password-Based Key Derivation Algorithm) settings for keyslots.
 * Works only with LUKS device handles (both versions).
 *
 * @param type type of device (see @link crypt-type @endlink)
 *
 * @return struct on success or NULL value otherwise.
 *
 */
const struct crypt_pbkdf_type *crypt_get_pbkdf_default(const char *type);

/**
 * Get current PBKDF (Password-Based Key Derivation Algorithm) settings for keyslots.
 * Works only with LUKS device handles (both versions).
 *
 * @param cd crypt device handle
 *
 * @return struct on success or NULL value otherwise.
 *
 */
const struct crypt_pbkdf_type *crypt_get_pbkdf_type(struct crypt_device *cd);

/**
 * Set how long should cryptsetup iterate in PBKDF2 function.
 * Default value heads towards the iterations which takes around 1 second.
 * \b Deprecated, only for backward compatibility.
 * Use @link crypt_set_pbkdf_type @endlink.
 *
 * @param cd crypt device handle
 * @param iteration_time_ms the time in ms
 *
 * @note If the time value is not acceptable for active PBKDF, value is quietly ignored.
 */
void crypt_set_iteration_time(struct crypt_device *cd, uint64_t iteration_time_ms);

/**
 * Helper to lock/unlock memory to avoid swap sensitive data to disk.
 * \b Deprecated, only for backward compatibility. Memory with keys are locked automatically.
 *
 * @param cd crypt device handle, can be @e NULL
 * @param lock 0 to unlock otherwise lock memory
 *
 * @returns Value indicating whether the memory is locked (function can be called multiple times).
 *
 * @note Only root can do this.
 * @note It locks/unlocks all process memory, not only crypt context.
 */
int crypt_memory_lock(struct crypt_device *cd, int lock) __attribute__((deprecated));

/**
 * Set global lock protection for on-disk metadata (file-based locking).
 *
 * @param cd crypt device handle, can be @e NULL
 * @param enable 0 to disable locking otherwise enable it (default)
 *
 * @returns @e 0 on success or negative errno value otherwise.
 *
 * @note Locking applied only for some metadata formats (LUKS2).
 * @note The switch is global on the library level.
 * 	 In current version locking can be only switched off and cannot be switched on later.
 */
int crypt_metadata_locking(struct crypt_device *cd, int enable);

/**
 * Set metadata header area sizes. This applies only to LUKS2.
 * These values limit amount of metadata anf number of supportable keyslots.
 *
 * @param cd crypt device handle, can be @e NULL
 * @param metadata_size size in bytes of JSON area + 4k binary header
 * @param keyslots_size size in bytes of binary keyslots area
 *
 * @returns @e 0 on success or negative errno value otherwise.
 *
 * @note The metadata area is stored twice and both copies contain 4k binary header.
 * Only 16,32,64,128,256,512,1024,2048 and 4096 kB value is allowed (see LUKS2 specification).
 * @note Keyslots area size must be multiple of 4k with maximum 128MB.
 */
int crypt_set_metadata_size(struct crypt_device *cd,
	uint64_t metadata_size,
	uint64_t keyslots_size);

/**
 * Get metadata header area sizes. This applies only to LUKS2.
 * These values limit amount of metadata anf number of supportable keyslots.
 *
 * @param cd crypt device handle
 * @param metadata_size size in bytes of JSON area + 4k binary header
 * @param keyslots_size size in bytes of binary keyslots area
 *
 * @returns @e 0 on success or negative errno value otherwise.
 */
int crypt_get_metadata_size(struct crypt_device *cd,
	uint64_t *metadata_size,
	uint64_t *keyslots_size);

/** @} */

/**
 * @defgroup crypt-type Cryptsetup on-disk format types
 * Set of functions, \#defines and structs related
 * to on-disk format types
 * @addtogroup crypt-type
 * @{
 */

/** plain crypt device, no on-disk header */
#define CRYPT_PLAIN "PLAIN"
/** LUKS version 1 header on-disk */
#define CRYPT_LUKS1 "LUKS1"
/** LUKS version 2 header on-disk */
#define CRYPT_LUKS2 "LUKS2"
/** loop-AES compatibility mode */
#define CRYPT_LOOPAES "LOOPAES"
/** dm-verity mode */
#define CRYPT_VERITY "VERITY"
/** TCRYPT (TrueCrypt-compatible and VeraCrypt-compatible) mode */
#define CRYPT_TCRYPT "TCRYPT"
/** INTEGRITY dm-integrity device */
#define CRYPT_INTEGRITY "INTEGRITY"
/** BITLK (BitLocker-compatible mode) */
#define CRYPT_BITLK "BITLK"
/** FVAULT2 (FileVault2-compatible mode) */
#define CRYPT_FVAULT2 "FVAULT2"

/** LUKS any version */
#define CRYPT_LUKS NULL

/**
 * Get device type
 *
 * @param cd crypt device handle
 * @return string according to device type or @e NULL if not known.
 */
const char *crypt_get_type(struct crypt_device *cd);

/**
 * Get device default LUKS type
 *
 * @return string according to device type (CRYPT_LUKS1 or CRYPT_LUKS2).
 */
const char *crypt_get_default_type(void);

/**
 * @defgroup crypt-hw-encryption-types HW encryption type
 * @addtogroup crypt-hw-encryption-types
 * @{
 */
/** SW encryption, no OPAL encryption in place (default) */
#define CRYPT_SW_ONLY        INT16_C(0)
/** OPAL HW encryption only (no SW encryption!) */
#define CRYPT_OPAL_HW_ONLY   INT16_C(1)
/** SW encryption stacked over OPAL HW encryption  */
#define CRYPT_SW_AND_OPAL_HW INT16_C(2)
/** @} */

/**
 * Get HW encryption type
 *
 * @return HW encryption type (see @link crypt-hw-encryption-types @endlink)
 *         or negative errno otherwise.
 */
int crypt_get_hw_encryption_type(struct crypt_device *cd);

/**
 * Get HW encryption (like OPAL) key size (in bytes)
 *
 * @return key size or 0 if no HW encryption is used.
 */
int crypt_get_hw_encryption_key_size(struct crypt_device *cd);

/**
 *
 * Structure used as parameter for PLAIN device type.
 *
 * @see crypt_format
 */
struct crypt_params_plain {
	const char *hash;     /**< password hash function */
	uint64_t offset;      /**< offset in sectors */
	uint64_t skip;        /**< IV offset / initialization sector */
	uint64_t size;        /**< size of mapped device or @e 0 for autodetection */
	uint32_t sector_size; /**< sector size in bytes (@e 0 means 512 for compatibility) */
};

/**
 * Structure used as parameter for LUKS device type.
 *
 * @see crypt_format, crypt_load
 *
 * @note during crypt_format @e data_device attribute determines
 * 	 if the LUKS header is separated from encrypted payload device
 *
 */
struct crypt_params_luks1 {
	const char *hash;        /**< hash used in LUKS header */
	size_t data_alignment;   /**< data area alignment in 512B sectors, data offset is multiple of this */
	const char *data_device; /**< detached encrypted data device or @e NULL */
};

/**
 *
 * Structure used as parameter for loop-AES device type.
 *
 * @see crypt_format
 *
 */
struct crypt_params_loopaes {
	const char *hash; /**< key hash function */
	uint64_t offset;  /**< offset in sectors */
	uint64_t skip;    /**< IV offset / initialization sector */
};

/**
 *
 * Structure used as parameter for dm-verity device type.
 *
 * @see crypt_format, crypt_load
 *
 */
struct crypt_params_verity {
	const char *hash_name;     /**< hash function */
	const char *data_device;   /**< data_device (CRYPT_VERITY_CREATE_HASH) */
	const char *hash_device;   /**< hash_device (output only) */
	const char *fec_device;    /**< fec_device (output only) */
	const char *salt;          /**< salt */
	uint32_t salt_size;        /**< salt size (in bytes) */
	uint32_t hash_type;        /**< in-kernel hashing type */
	uint32_t data_block_size;  /**< data block size (in bytes) */
	uint32_t hash_block_size;  /**< hash block size (in bytes) */
	uint64_t data_size;        /**< data area size (in data blocks) */
	uint64_t hash_area_offset; /**< hash/header offset (in bytes) */
	uint64_t fec_area_offset;  /**< FEC/header offset (in bytes) */
	uint32_t fec_roots;        /**< Reed-Solomon FEC roots */
	uint32_t flags;            /**< CRYPT_VERITY* flags */
};

/** No on-disk header (only hashes) */
#define CRYPT_VERITY_NO_HEADER   (UINT32_C(1) << 0)
/** Verity hash in userspace before activation */
#define CRYPT_VERITY_CHECK_HASH  (UINT32_C(1) << 1)
/** Create hash - format hash device */
#define CRYPT_VERITY_CREATE_HASH (UINT32_C(1) << 2)
/** Root hash signature required for activation */
#define CRYPT_VERITY_ROOT_HASH_SIGNATURE (UINT32_C(1) << 3)

/**
 *
 * Structure used as parameter for TCRYPT device type.
 *
 * @see crypt_load
 *
 */
struct crypt_params_tcrypt {
	const char *passphrase;    /**< passphrase to unlock header (input only) */
	size_t passphrase_size;    /**< passphrase size (input only, max length is 64) */
	const char **keyfiles;     /**< keyfile paths to unlock header (input only) */
	unsigned int keyfiles_count;/**< keyfiles count (input only) */
	const char *hash_name;     /**< hash function for PBKDF */
	const char *cipher;        /**< cipher chain c1[-c2[-c3]] */
	const char *mode;          /**< cipher block mode */
	size_t key_size;           /**< key size in bytes (the whole chain) */
	uint32_t flags;            /**< CRYPT_TCRYPT* flags */
	uint32_t veracrypt_pim;    /**< VeraCrypt Personal Iteration Multiplier */
};

/** Include legacy modes when scanning for header */
#define CRYPT_TCRYPT_LEGACY_MODES    (UINT32_C(1) << 0)
/** Try to load hidden header (describing hidden device) */
#define CRYPT_TCRYPT_HIDDEN_HEADER   (UINT32_C(1) << 1)
/** Try to load backup header */
#define CRYPT_TCRYPT_BACKUP_HEADER   (UINT32_C(1) << 2)
/** Device contains encrypted system (with boot loader) */
#define CRYPT_TCRYPT_SYSTEM_HEADER   (UINT32_C(1) << 3)
/** Include VeraCrypt modes when scanning for header,
 *  all other TCRYPT flags applies as well.
 *  VeraCrypt device is reported as TCRYPT type.
 */
#define CRYPT_TCRYPT_VERA_MODES      (UINT32_C(1) << 4)

/**
 *
 * Structure used as parameter for dm-integrity device type.
 *
 * @see crypt_format, crypt_load
 *
 * @note In bitmap tracking mode, the journal is implicitly disabled.
 *       As an ugly workaround for compatibility, journal_watermark is overloaded
 *       to mean 512-bytes sectors-per-bit and journal_commit_time means bitmap flush time.
 *       All other journal parameters are not applied in the bitmap mode.
 */
struct crypt_params_integrity {
	uint64_t journal_size;               /**< size of journal in bytes */
	unsigned int journal_watermark;      /**< journal flush watermark in percents; in bitmap mode sectors-per-bit  */
	unsigned int journal_commit_time;    /**< journal commit time (or bitmap flush time) in ms */
	uint32_t interleave_sectors;         /**< number of interleave sectors (power of two) */
	uint32_t tag_size;                   /**< tag size per-sector in bytes */
	uint32_t sector_size;                /**< sector size in bytes */
	uint32_t buffer_sectors;             /**< number of sectors in one buffer */
	const char *integrity;               /**< integrity algorithm, NULL for LUKS2 */
	uint32_t integrity_key_size;         /**< integrity key size in bytes, info only */

	const char *journal_integrity;       /**< journal integrity algorithm */
	const char *journal_integrity_key;   /**< journal integrity key, only for crypt_load */
	uint32_t journal_integrity_key_size; /**< journal integrity key size in bytes, only for crypt_load */

	const char *journal_crypt;           /**< journal encryption algorithm */
	const char *journal_crypt_key;       /**< journal crypt key, only for crypt_load */
	uint32_t journal_crypt_key_size;     /**< journal crypt key size in bytes, only for crypt_load */
};

/**
 * Structure used as parameter for LUKS2 device type.
 *
 * @see crypt_format, crypt_load
 *
 * @note during crypt_format @e data_device attribute determines
 * 	 if the LUKS2 header is separated from encrypted payload device
 *
 */
struct crypt_params_luks2 {
	const struct crypt_pbkdf_type *pbkdf; /**< PBKDF (and hash) parameters or @e NULL*/
	const char *integrity;                /**< integrity algorithm or @e NULL */
	const struct crypt_params_integrity *integrity_params; /**< Data integrity parameters or @e NULL*/
	size_t data_alignment;   /**< data area alignment in 512B sectors, data offset is multiple of this */
	const char *data_device; /**< detached encrypted data device or @e NULL */
	uint32_t sector_size;    /**< encryption sector size, 0 triggers auto-detection for optimal encryption sector size */
	const char *label;       /**< header label or @e NULL*/
	const char *subsystem;   /**< header subsystem label or @e NULL*/
};

/**
 * Structure used as parameter for OPAL (HW encrypted) device type.
 *
 * @see crypt_format_luks2_opal
 *
 */
struct crypt_params_hw_opal {
	const char *admin_key;   /**< admin key */
	size_t admin_key_size;   /**< admin key size in bytes */
	size_t user_key_size;    /**< user authority key size part in bytes */
};
/** @} */

/**
 * @defgroup crypt-actions Cryptsetup device context actions
 * Set of functions for formatting and manipulating with specific crypt_type
 * @addtogroup crypt-actions
 * @{
 */

/**
 * Create (format) new crypt device (and possible header on-disk) but do not activate it.
 *
 * @pre @e cd contains initialized and not formatted device context (device type must @b not be set)
 *
 * @param cd crypt device handle
 * @param type type of device (optional params struct must be of this type)
 * @param cipher (e.g. "aes")
 * @param cipher_mode including IV specification (e.g. "xts-plain")
 * @param uuid requested UUID or @e NULL if it should be generated
 * @param volume_key pre-generated volume key or @e NULL if it should be generated (only for LUKS)
 * @param volume_key_size size of volume key in bytes.
 * @param params crypt type specific parameters (see @link crypt-type @endlink)
 *
 * @returns @e 0 on success or negative errno value otherwise.
 *
 * @note Note that crypt_format does not create LUKS keyslot (any version). To create keyslot
 *	 call any crypt_keyslot_add_* function.
 * @note For VERITY @link crypt-type @endlink, only uuid parameter is used, other parameters
 * 	are ignored and verity specific attributes are set through mandatory params option.
 */
int crypt_format(struct crypt_device *cd,
	const char *type,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_key,
	size_t volume_key_size,
	void *params);

/**
 * Create (format) new LUKS2 crypt device over HW OPAL device but do not activate it.
 *
 * @pre @e cd contains initialized and not formatted device context (device type must @b not be set)
 *
 * @param cd crypt device handle
 * @param cipher for SW encryption (e.g. "aes") or NULL for HW encryption only
 * @param cipher_mode including IV specification (e.g. "xts-plain") or NULL for HW encryption only
 * @param uuid requested UUID or @e NULL if it should be generated
 * @param volume_keys pre-generated volume keys or @e NULL if it should be generated (only for LUKS2 SW encryption)
 * @param volume_keys_size size of volume keys in bytes (only for SW encryption).
 * @param params LUKS2 crypt type specific parameters (see @link crypt-type @endlink)
 * @param opal_params OPAL specific parameters
 *
 * @returns @e 0 on success or negative errno value otherwise.
 *
 * @note Note that crypt_format_luks2_opal does not create LUKS keyslot.
 *       To create keyslot call any crypt_keyslot_add_* function.
 */
int crypt_format_luks2_opal(struct crypt_device *cd,
	const char *cipher,
	const char *cipher_mode,
	const char *uuid,
	const char *volume_keys,
	size_t volume_keys_size,
	struct crypt_params_luks2 *params,
	struct crypt_params_hw_opal *opal_params);

/**
 * Set format compatibility flags.
 *
 * @param cd crypt device handle
 * @param flags CRYPT_COMPATIBILITY_* flags
 */
void crypt_set_compatibility(struct crypt_device *cd, uint32_t flags);

/**
 * Get compatibility flags.
 *
 * @param cd crypt device handle
 *
 * @returns compatibility flags
 */
uint32_t crypt_get_compatibility(struct crypt_device *cd);

/** dm-integrity device uses less effective (legacy) padding (old kernels) */
#define CRYPT_COMPAT_LEGACY_INTEGRITY_PADDING (UINT32_C(1) << 0)
/** dm-integrity device does not protect superblock with HMAC (old kernels) */
#define CRYPT_COMPAT_LEGACY_INTEGRITY_HMAC (UINT32_C(1) << 1)
/** dm-integrity allow recalculating of volumes with HMAC keys (old kernels) */
#define CRYPT_COMPAT_LEGACY_INTEGRITY_RECALC (UINT32_C(1) << 2)

/**
 * Convert to new type for already existing device.
 *
 * @param cd crypt device handle
 * @param type type of device (optional params struct must be of this type)
 * @param params crypt type specific parameters (see @link crypt-type @endlink)
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @note Currently, only LUKS1->LUKS2 and LUKS2->LUKS1 conversions are supported.
 *	 Not all LUKS2 devices may be converted back to LUKS1. To make such a conversion
 *	 possible all active LUKS2 keyslots must be in LUKS1 compatible mode (i.e. pbkdf
 *	 type must be PBKDF2) and device cannot be formatted with any authenticated
 *	 encryption mode.
 *
 * @note Device must be offline for conversion. UUID change is not possible for active
 *	 devices.
 */
int crypt_convert(struct crypt_device *cd,
	const char *type,
	void *params);

/**
 * Set new UUID for already existing device.
 *
 * @param cd crypt device handle
 * @param uuid requested UUID or @e NULL if it should be generated
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @note Currently, only LUKS device type are supported
 */
int crypt_set_uuid(struct crypt_device *cd,
	const char *uuid);

/**
 * Set new labels (label and subsystem) for already existing device.
 *
 * @param cd crypt device handle
 * @param label requested label or @e NULL
 * @param subsystem requested subsystem label or @e NULL
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @note Currently, only LUKS2 device type is supported
 */
int crypt_set_label(struct crypt_device *cd,
	const char *label,
	const char *subsystem);

/**
 * Get the label of an existing device.
 *
 * @param cd crypt device handle
 *
 * @return label, or @e NULL otherwise
 */
const char *crypt_get_label(struct crypt_device *cd);

/**
 * Get the subsystem of an existing device.
 *
 * @param cd crypt device handle
 *
 * @return subsystem, or @e NULL otherwise
 */
const char *crypt_get_subsystem(struct crypt_device *cd);

/**
 * Enable or disable loading of volume keys via kernel keyring. When set to
 * 'enabled' library loads key in kernel keyring first and pass the key
 * description to dm-crypt instead of binary key copy. If set to 'disabled'
 * library fallbacks to old method of loading volume key directly in
 * dm-crypt target.
 *
 * @param cd crypt device handle, can be @e NULL
 * @param enable 0 to disable loading of volume keys via kernel keyring
 * 	  (classical method) otherwise enable it (default)
 *
 * @returns @e 0 on success or negative errno value otherwise.
 *
 * @note Currently loading of volume keys via kernel keyring is supported
 * 	 (and enabled by default) only for LUKS2 devices.
 * @note The switch is global on the library level.
 */
int crypt_volume_key_keyring(struct crypt_device *cd, int enable);

/**
 * Load crypt device parameters from on-disk header.
 *
 * @param cd crypt device handle
 * @param requested_type @link crypt-type @endlink or @e NULL for all known
 * @param params crypt type specific parameters (see @link crypt-type @endlink)
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @post In case LUKS header is read successfully but payload device is too small
 * error is returned and device type in context is set to @e NULL
 *
 * @note Note that load works only for device types with on-disk metadata.
 * @note Function does not print visible error message if metadata is not present.
 *
 */
int crypt_load(struct crypt_device *cd,
	const char *requested_type,
	void *params);

/**
 * Try to repair crypt device LUKS on-disk header if invalid.
 *
 * @param cd crypt device handle
 * @param requested_type @link crypt-type @endlink or @e NULL for all known
 * @param params crypt type specific parameters (see @link crypt-type @endlink)
 *
 * @returns 0 on success or negative errno value otherwise.
 *
 * @note For LUKS2 device crypt_repair bypass blkid checks and
 * 	 perform auto-recovery even though there're third party device
 * 	 signatures found by blkid probes. Currently the crypt_repair on LUKS2
 * 	 works only if exactly one header checksum does not match or exactly
 * 	 one header is missing.
 */
int crypt_repair(struct crypt_device *cd,
	const char *requested_type,
	void *params);

/**
 * Resize crypt device.
 *
 * @param cd - crypt device handle
 * @param name - name of device to resize
 * @param new_size - new device size in sectors or @e 0 to use all of the underlying device size
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note Most notably it returns -EPERM when device was activated with volume key
 * 	 in kernel keyring and current device handle (context) doesn't have verified key
 * 	 loaded in kernel. To load volume key for already active device use any of
 * 	 @link crypt_activate_by_passphrase @endlink, @link crypt_activate_by_keyfile @endlink,
 * 	 @link crypt_activate_by_keyfile_offset @endlink, @link crypt_activate_by_volume_key @endlink,
 * 	 @link crypt_activate_by_keyring @endlink or @link crypt_activate_by_token @endlink with flag
 * 	 @e CRYPT_ACTIVATE_KEYRING_KEY raised and @e name parameter set to @e NULL.
 */
int crypt_resize(struct crypt_device *cd,
	const char *name,
	uint64_t new_size);

/**
 * Suspend crypt device.
 *
 * @param cd crypt device handle, can be @e NULL
 * @param name name of device to suspend
 *
 * @return 0 on success or negative errno value otherwise.
 *
 * @note Only LUKS device type is supported
 *
 */
int crypt_suspend(struct crypt_device *cd,
	const char *name);

/**
 * Resume crypt device using passphrase.
 *
 *
 * @param cd crypt device handle
 * @param name name of device to resume
 * @param keyslot requested keyslot or CRYPT_ANY_SLOT
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of @e passphrase (binary data)
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note Only LUKS device type is supported
 */
int crypt_resume_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size);

/**
 * Resume crypt device using key file.
 *
 * @param cd crypt device handle
 * @param name name of device to resume
 * @param keyslot requested keyslot or CRYPT_ANY_SLOT
 * @param keyfile key file used to unlock volume key
 * @param keyfile_size number of bytes to read from keyfile, 0 is unlimited
 * @param keyfile_offset number of bytes to skip at start of keyfile
 *
 * @return unlocked key slot number or negative errno otherwise.
 */
int crypt_resume_by_keyfile_device_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset);

/**
 * Backward compatible crypt_resume_by_keyfile_device_offset() (with size_t offset).
 */
int crypt_resume_by_keyfile_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset);

/**
 * Backward compatible crypt_resume_by_keyfile_device_offset() (without offset).
 */
int crypt_resume_by_keyfile(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size);
/**
 * Resume crypt device using provided volume key.
 *
 * @param cd crypt device handle
 * @param name name of device to resume
 * @param volume_key provided volume key
 * @param volume_key_size size of volume_key
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_resume_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size);
/**
 * Resume crypt device using LUKS2 token.
 *
 * @param cd LUKS2 crypt device handle
 * @param name name of device to resume
 * @param type restrict type of token, if @e NULL all types are allowed
 * @param pin passphrase (or PIN) to unlock token (may be binary data)
 * @param pin_size size of @e pin
 * @param usrptr provided identification in callback
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note EPERM errno means token provided passphrase successfully, but
 *       passphrase did not unlock any keyslot associated with the token.
 *
 * @note ENOENT errno means no token (or subsequently assigned keyslot) was
 *       eligible to resume LUKS2 device.
 *
 * @note ENOANO errno means that token is PIN protected and was either missing
 *       (NULL) or wrong.
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system to unlock keyslot.
 *
 * @note with @param token set to CRYPT_ANY_TOKEN libcryptsetup runs best effort loop
 *       to resume device using any available token. It may happen that various token handlers
 *       return different error codes. At the end loop returns error codes in the following
 *       order (from the most significant to the least) any negative errno except those
 *       listed below, non negative token id (success), -ENOANO, -EAGAIN, -EPERM, -ENOENT.
 */
int crypt_resume_by_token_pin(struct crypt_device *cd,
	const char *name,
	const char *type,
	int token,
	const char *pin,
	size_t pin_size,
	void *usrptr);

/**
 * Resume crypt device using keyslot context.
 *
 * @param cd crypt device handle
 * @param name name of device to resume
 * @param keyslot requested keyslot to check or @e CRYPT_ANY_SLOT, keyslot is
 *        ignored for unlock methods not based on passphrase
 * @param kc keyslot context providing volume key or passphrase.
 *
 * @return unlocked key slot number for passphrase-based unlock, zero for other
 *         unlock methods (e.g. volume key context) or negative errno on error.
 */
int crypt_resume_by_keyslot_context(struct crypt_device *cd,
			       const char *name,
			       int keyslot,
			       struct crypt_keyslot_context *kc);
/** @} */

/**
 * @defgroup crypt-keyslot LUKS keyslots
 * @addtogroup crypt-keyslot
 * @{
 */

/** iterate through all keyslots and find first one that fits */
#define CRYPT_ANY_SLOT -1

/**
 * Add key slot using provided passphrase.
 *
 * @pre @e cd contains initialized and formatted LUKS device context
 *
 * @param cd crypt device handle
 * @param keyslot requested keyslot or @e CRYPT_ANY_SLOT
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of passphrase (binary data)
 * @param new_passphrase passphrase for new keyslot
 * @param new_passphrase_size size of @e new_passphrase (binary data)
 *
 * @return allocated key slot number or negative errno otherwise.
 */
int crypt_keyslot_add_by_passphrase(struct crypt_device *cd,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size);

/**
 * Change defined key slot using provided passphrase.
 *
 * @pre @e cd contains initialized and formatted LUKS device context
 *
 * @param cd crypt device handle
 * @param keyslot_old old keyslot or @e CRYPT_ANY_SLOT
 * @param keyslot_new new keyslot (can be the same as old)
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of passphrase (binary data)
 * @param new_passphrase passphrase for new keyslot
 * @param new_passphrase_size size of @e new_passphrase (binary data)
 *
 * @return allocated key slot number or negative errno otherwise.
 */
int crypt_keyslot_change_by_passphrase(struct crypt_device *cd,
	int keyslot_old,
	int keyslot_new,
	const char *passphrase,
	size_t passphrase_size,
	const char *new_passphrase,
	size_t new_passphrase_size);

/**
* Add key slot using provided key file path.
 *
 * @pre @e cd contains initialized and formatted LUKS device context
 *
 * @param cd crypt device handle
 * @param keyslot requested keyslot or @e CRYPT_ANY_SLOT
 * @param keyfile key file used to unlock volume key
 * @param keyfile_size number of bytes to read from keyfile, @e 0 is unlimited
 * @param keyfile_offset number of bytes to skip at start of keyfile
 * @param new_keyfile keyfile for new keyslot
 * @param new_keyfile_size number of bytes to read from @e new_keyfile, @e 0 is unlimited
 * @param new_keyfile_offset number of bytes to skip at start of new_keyfile
 *
 * @return allocated key slot number or negative errno otherwise.
 */
int crypt_keyslot_add_by_keyfile_device_offset(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	const char *new_keyfile,
	size_t new_keyfile_size,
	uint64_t new_keyfile_offset);

/**
 * Backward compatible crypt_keyslot_add_by_keyfile_device_offset() (with size_t offset).
 */
int crypt_keyslot_add_by_keyfile_offset(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset,
	const char *new_keyfile,
	size_t new_keyfile_size,
	size_t new_keyfile_offset);

/**
 * Backward compatible crypt_keyslot_add_by_keyfile_device_offset() (without offset).
 */
int crypt_keyslot_add_by_keyfile(struct crypt_device *cd,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	const char *new_keyfile,
	size_t new_keyfile_size);

/**
 * Add key slot using provided volume key.
 *
 * @pre @e cd contains initialized and formatted LUKS device context
 *
 * @param cd crypt device handle
 * @param keyslot requested keyslot or CRYPT_ANY_SLOT
 * @param volume_key provided volume key or @e NULL if used after crypt_format
 * @param volume_key_size size of volume_key
 * @param passphrase passphrase for new keyslot
 * @param passphrase_size size of passphrase
 *
 * @return allocated key slot number or negative errno otherwise.
 */
int crypt_keyslot_add_by_volume_key(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size);

/** create keyslot with volume key not associated with current dm-crypt segment */
#define CRYPT_VOLUME_KEY_NO_SEGMENT (UINT32_C(1) << 0)

/** create keyslot with new volume key and assign it to current dm-crypt segment */
#define CRYPT_VOLUME_KEY_SET (UINT32_C(1) << 1)

/** Assign key to first matching digest before creating new digest */
#define CRYPT_VOLUME_KEY_DIGEST_REUSE (UINT32_C(1) << 2)

/**
 * Add key slot using provided key.
 *
 * @pre @e cd contains initialized and formatted LUKS2 device context
 *
 * @param cd crypt device handle
 * @param keyslot requested keyslot or CRYPT_ANY_SLOT
 * @param volume_key provided volume key or @e NULL (see note below)
 * @param volume_key_size size of volume_key
 * @param passphrase passphrase for new keyslot
 * @param passphrase_size size of passphrase
 * @param flags key flags to set
 *
 * @return allocated key slot number or negative errno otherwise.
 *
 * @note in case volume_key is @e NULL following first matching rule will apply:
 * @li if cd is device handle used in crypt_format() by current process, the volume
 *     key generated (or passed) in crypt_format() will be stored in keyslot.
 * @li if CRYPT_VOLUME_KEY_NO_SEGMENT flag is raised the new volume_key will be
 *     generated and stored in keyslot. The keyslot will become unbound (unusable to
 *     dm-crypt device activation).
 * @li fails with -EINVAL otherwise
 *
 * @warning CRYPT_VOLUME_KEY_SET flag force updates volume key. It is @b not @b reencryption!
 * 	    By doing so you will most probably destroy your ciphertext data device. It's supposed
 * 	    to be used only in wrapped keys scheme for key refresh process where real (inner) volume
 * 	    key stays untouched. It may be involved on active @e keyslot which makes the (previously
 * 	    unbound) keyslot new regular keyslot.
 */
int crypt_keyslot_add_by_key(struct crypt_device *cd,
	int keyslot,
	const char *volume_key,
	size_t volume_key_size,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags);

/**
 * @defgroup crypt-keyslot-context Crypt keyslot context
 * @addtogroup crypt-keyslot-context
 * @{
 */

/**
 * Release crypt keyslot context and used memory.
 *
 * @param kc crypt keyslot context
 */
void crypt_keyslot_context_free(struct crypt_keyslot_context *kc);

/**
 * Initialize keyslot context via passphrase.
 *
 * @param cd crypt device handle initialized to LUKS device context
 * @param passphrase passphrase for a keyslot
 * @param passphrase_size size of passphrase
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_PASSPHRASE
 *
 * @return zero on success or negative errno otherwise.
 *
 * @note The original buffer containing passphrase passed in parameters does
 * 	 not have to be valid after context initialization. The context
 * 	 contains copy of the original before freed with @link crypt_keyslot_context_free @endlink.
 */
int crypt_keyslot_context_init_by_passphrase(struct crypt_device *cd,
	const char *passphrase,
	size_t passphrase_size,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via key file path.
 *
 * @param cd crypt device handle initialized to LUKS device context
 *
 * @param keyfile key file with passphrase for a keyslot
 * @param keyfile_size number of bytes to read from keyfile, @e 0 is unlimited
 * @param keyfile_offset number of bytes to skip at start of keyfile
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_KEYFILE
 *
 * @return zero on success or negative errno otherwise.
 */
int crypt_keyslot_context_init_by_keyfile(struct crypt_device *cd,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via LUKS2 token.
 *
 * @param cd crypt device handle initialized to LUKS2 device context
 *
 * @param token token providing passphrase for a keyslot or CRYPT_ANY_TOKEN
 * @param type restrict type of token, if @e NULL all types are allowed
 * @param pin passphrase (or PIN) to unlock token (may be binary data)
 * @param pin_size size of @e pin
 * @param usrptr provided identification in callback
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_TOKEN
 *
 * @return zero on success or negative errno otherwise.
 */
int crypt_keyslot_context_init_by_token(struct crypt_device *cd,
	int token,
	const char *type,
	const char *pin, size_t pin_size,
	void *usrptr,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via key.
 *
 * @param cd crypt device handle initialized to LUKS device context
 *
 * @param volume_key provided volume key or @e NULL if used after crypt_format
 *        or with CRYPT_VOLUME_KEY_NO_SEGMENT flag
 * @param volume_key_size size of volume_key
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_KEY
 *
 * @return zero on success or negative errno otherwise.
 */
int crypt_keyslot_context_init_by_volume_key(struct crypt_device *cd,
	const char *volume_key,
	size_t volume_key_size,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via signed key.
 *
 * @param cd crypt device handle initialized to device context
 *
 * @param volume_key provided volume key
 * @param volume_key_size size of volume_key
 * @param signature buffer with signature for the key
 * @param signature_size bsize of signature buffer
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_SIGNED_KEY
 *
 * @return zero on success or negative errno otherwise.
 *
 * @note currently supported only with VERITY devices.
 */
int crypt_keyslot_context_init_by_signed_key(struct crypt_device *cd,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via passphrase stored in a keyring.
 *
 * @param cd crypt device handle initialized to LUKS device context
 *
 * @param key_description kernel keyring key description library should look
 *        for passphrase in
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_KEYRING
 *
 * @return zero on success or negative errno otherwise.
 */
int crypt_keyslot_context_init_by_keyring(struct crypt_device *cd,
	const char *key_description,
	struct crypt_keyslot_context **kc);

/**
 * Initialize keyslot context via volume key stored in a keyring.
 *
 * @param cd crypt device handle initialized to LUKS device context
 *
 * @param key_description kernel keyring key description library should look
 *        for passphrase in. The key can be passed either as number in ASCII,
 *        or a text representation in the form "%<key_type>:<key_name>"
 * @param kc returns crypt keyslot context handle type CRYPT_KC_TYPE_KEYRING
 *
 * @return zero on success or negative errno otherwise.
 */
int crypt_keyslot_context_init_by_vk_in_keyring(struct crypt_device *cd,
	const char *key_description,
	struct crypt_keyslot_context **kc);

/**
 * Get error code per keyslot context from last failed call.
 *
 * @note If @link crypt_keyslot_add_by_keyslot_context @endlink passed with
 * 	 no negative return code. The return value of this function is undefined.
 *
 * @param kc keyslot context involved in failed @link crypt_keyslot_add_by_keyslot_context @endlink
 *
 * @return Negative errno if keyslot context caused a failure, zero otherwise.
 */
int crypt_keyslot_context_get_error(struct crypt_keyslot_context *kc);

/**
 * Set new pin to token based keyslot context.
 *
 * @note Use when @link crypt_keyslot_add_by_keyslot_context @endlink failed
 *	 and token keyslot context returned -ENOANO error code via
 *	 @link crypt_keyslot_context_get_error @endlink.
 *
 * @param cd crypt device handle initialized to LUKS2 device context
 * @param pin passphrase (or PIN) to unlock token (may be binary data)
 * @param pin_size size of @e pin
 * @param kc LUKS2 keyslot context (only @link CRYPT_KC_TYPE_TOKEN @endlink is allowed)
 *
 * @return zero on success or negative errno otherwise
 */
int crypt_keyslot_context_set_pin(struct crypt_device *cd,
	const char *pin, size_t pin_size,
	struct crypt_keyslot_context *kc);

/**
 * @defgroup crypt-keyslot-context-types Crypt keyslot context types
 * @addtogroup crypt-keyslot-context-types
 * @{
 */
/** keyslot context initialized by passphrase (@link crypt_keyslot_context_init_by_passphrase @endlink) */
#define CRYPT_KC_TYPE_PASSPHRASE INT16_C(1)
/** keyslot context initialized by keyfile (@link crypt_keyslot_context_init_by_keyfile @endlink) */
#define CRYPT_KC_TYPE_KEYFILE    INT16_C(2)
/** keyslot context initialized by token (@link crypt_keyslot_context_init_by_token @endlink) */
#define CRYPT_KC_TYPE_TOKEN      INT16_C(3)
/** keyslot context initialized by volume key or unbound key (@link crypt_keyslot_context_init_by_volume_key @endlink) */
#define CRYPT_KC_TYPE_KEY        INT16_C(4)
/** keyslot context initialized by description of a keyring key
 * (@link crypt_keyslot_context_init_by_keyring @endlink)
 */
#define CRYPT_KC_TYPE_KEYRING    INT16_C(5)
/** keyslot context initialized by description of a keyring key containing the volume key
 * (@link crypt_keyslot_context_init_by_vk_in_keyring @endlink)
 */
#define CRYPT_KC_TYPE_VK_KEYRING    INT16_C(6)
/** keyslot context initialized by signed key (@link crypt_keyslot_context_init_by_signed_key @endlink) */
#define CRYPT_KC_TYPE_SIGNED_KEY    INT16_C(7)
/** @} */

/**
 * Get type identifier for crypt keyslot context.
 *
 * @param kc keyslot context
 *
 * @return crypt keyslot context type id (see @link crypt-keyslot-context-types @endlink) or negative errno otherwise.
 */
int crypt_keyslot_context_get_type(const struct crypt_keyslot_context *kc);
/** @} */

/**
 * Add key slot by volume key provided by keyslot context (kc). New
 * keyslot will be protected by passphrase provided by new keyslot context (new_kc).
 * See @link crypt-keyslot-context @endlink for context initialization routines.
 *
 * @pre @e cd contains initialized and formatted LUKS device context.
 *
 * @param cd crypt device handle
 * @param keyslot_existing existing keyslot or CRYPT_ANY_SLOT to get volume key from.
 * @param kc keyslot context providing volume key.
 * @param keyslot_new new keyslot or CRYPT_ANY_SLOT (first free number is used).
 * @param new_kc keyslot context providing passphrase for new keyslot.
 * @param flags key flags to set
 *
 * @return allocated key slot number or negative errno otherwise.
 *
 * @note new_kc can not be @e CRYPT_KC_TYPE_KEY type keyslot context.
 *
 * @note For kc parameter with type @e CRYPT_KC_TYPE_KEY the keyslot_existing
 *       parameter is ignored.
 *
 * @note in case there is no active LUKS keyslot to get existing volume key from, one of following must apply:
 * 	 @li @e cd must be device handle used in crypt_format() by current process (it holds reference to generated volume key)
 * 	 @li kc must be of @e CRYPT_KC_TYPE_KEY type with valid volume key.
 *
 * @note With CRYPT_VOLUME_KEY_NO_SEGMENT flag raised and kc of type @e CRYPT_KC_TYPE_KEY with @e volume_key set to @e NULL
 *     the new volume_key will be generated and stored in new keyslot. The keyslot will become unbound (unusable to
 *     dm-crypt device activation).
 *
 * @warning CRYPT_VOLUME_KEY_SET flag force updates volume key. It is @b not @b reencryption!
 * 	    By doing so you will most probably destroy your ciphertext data device. It's supposed
 * 	    to be used only in wrapped keys scheme for key refresh process where real (inner) volume
 * 	    key stays untouched. It may be involved on active @e keyslot which makes the (previously
 * 	    unbound) keyslot new regular keyslot.
 */
int crypt_keyslot_add_by_keyslot_context(struct crypt_device *cd,
	int keyslot_existing,
	struct crypt_keyslot_context *kc,
	int keyslot_new,
	struct crypt_keyslot_context *new_kc,
	uint32_t flags);

/**
 * Destroy (and disable) key slot.
 *
 * @pre @e cd contains initialized and formatted LUKS device context
 *
 * @param cd crypt device handle
 * @param keyslot requested key slot to destroy
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note Note that there is no passphrase verification used.
 */
int crypt_keyslot_destroy(struct crypt_device *cd, int keyslot);
/** @} */

/**
 * @defgroup crypt-aflags Device runtime attributes
 * Activation flags
 * @addtogroup crypt-aflags
 * @{
 */

/** device is read only */
#define CRYPT_ACTIVATE_READONLY (UINT32_C(1) << 0)
/** only reported for device without uuid */
#define CRYPT_ACTIVATE_NO_UUID  (UINT32_C(1) << 1)
/** activate even if cannot grant exclusive access (DANGEROUS) */
#define CRYPT_ACTIVATE_SHARED   (UINT32_C(1) << 2)
/** enable discards aka TRIM */
#define CRYPT_ACTIVATE_ALLOW_DISCARDS (UINT32_C(1) << 3)
/** skip global udev rules in activation ("private device"), input only */
#define CRYPT_ACTIVATE_PRIVATE (UINT32_C(1) << 4)
/** corruption detected (verity), output only */
#define CRYPT_ACTIVATE_CORRUPTED (UINT32_C(1) << 5)
/** use same_cpu_crypt option for dm-crypt */
#define CRYPT_ACTIVATE_SAME_CPU_CRYPT (UINT32_C(1) << 6)
/** use submit_from_crypt_cpus for dm-crypt */
#define CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS (UINT32_C(1) << 7)
/** dm-verity: ignore_corruption flag - ignore corruption, log it only */
#define CRYPT_ACTIVATE_IGNORE_CORRUPTION (UINT32_C(1) << 8)
/** dm-verity: restart_on_corruption flag - restart kernel on corruption */
#define CRYPT_ACTIVATE_RESTART_ON_CORRUPTION (UINT32_C(1) << 9)
/** dm-verity: ignore_zero_blocks - do not verify zero blocks */
#define CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS (UINT32_C(1) << 10)
/** key loaded in kernel keyring instead directly in dm-crypt */
#define CRYPT_ACTIVATE_KEYRING_KEY (UINT32_C(1) << 11)
/** dm-integrity: direct writes, do not use journal */
#define CRYPT_ACTIVATE_NO_JOURNAL (UINT32_C(1) << 12)
/** dm-integrity: recovery mode - no journal, no integrity checks */
#define CRYPT_ACTIVATE_RECOVERY (UINT32_C(1) << 13)
/** ignore persistently stored flags */
#define CRYPT_ACTIVATE_IGNORE_PERSISTENT (UINT32_C(1) << 14)
/** dm-verity: check_at_most_once - check data blocks only the first time */
#define CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE (UINT32_C(1) << 15)
/** allow activation check including unbound keyslots (keyslots without segments) */
#define CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY (UINT32_C(1) << 16)
/** dm-integrity: activate automatic recalculation */
#define CRYPT_ACTIVATE_RECALCULATE (UINT32_C(1) << 17)
/** reactivate existing and update flags, input only */
#define CRYPT_ACTIVATE_REFRESH	(UINT32_C(1) << 18)
/** Use global lock to serialize memory hard KDF on activation (OOM workaround) */
#define CRYPT_ACTIVATE_SERIALIZE_MEMORY_HARD_PBKDF (UINT32_C(1) << 19)
/** dm-integrity: direct writes, use bitmap to track dirty sectors */
#define CRYPT_ACTIVATE_NO_JOURNAL_BITMAP (UINT32_C(1) << 20)
/** device is suspended (key should be wiped from memory), output only */
#define CRYPT_ACTIVATE_SUSPENDED (UINT32_C(1) << 21)
/** use IV sector counted in sector_size instead of default 512 bytes sectors */
#define CRYPT_ACTIVATE_IV_LARGE_SECTORS (UINT32_C(1) << 22)
/** dm-verity: panic_on_corruption flag - panic kernel on corruption */
#define CRYPT_ACTIVATE_PANIC_ON_CORRUPTION (UINT32_C(1) << 23)
/** dm-crypt: bypass internal workqueue and process read requests synchronously. */
#define CRYPT_ACTIVATE_NO_READ_WORKQUEUE (UINT32_C(1) << 24)
/** dm-crypt: bypass internal workqueue and process write requests synchronously. */
#define CRYPT_ACTIVATE_NO_WRITE_WORKQUEUE (UINT32_C(1) << 25)
/** dm-integrity: reset automatic recalculation */
#define CRYPT_ACTIVATE_RECALCULATE_RESET (UINT32_C(1) << 26)
/** dm-verity: try to use tasklets */
#define CRYPT_ACTIVATE_TASKLETS (UINT32_C(1) << 27)
/** dm-crypt: use high-priority workqueues */
#define CRYPT_ACTIVATE_HIGH_PRIORITY (UINT32_C(1) << 28)
/** dm-verity: also restart/panic on error, use with RESTART_ON_CORRUPTION or PANIC_ON_CORRUPTION */
#define CRYPT_ACTIVATE_ERROR_AS_CORRUPTION (UINT32_C(1) << 29)

/**
 * Active device runtime attributes
 */
struct crypt_active_device {
	uint64_t offset;    /**< offset in sectors */
	uint64_t iv_offset; /**< IV initialization sector */
	uint64_t size;      /**< active device size */
	uint32_t flags;     /**< activation flags */
};

/**
 * Receive runtime attributes of active crypt device.
 *
 * @param cd crypt device handle (can be @e NULL)
 * @param name name of active device
 * @param cad preallocated active device attributes to fill
 *
 * @return @e 0 on success or negative errno value otherwise
 *
 */
int crypt_get_active_device(struct crypt_device *cd,
	const char *name,
	struct crypt_active_device *cad);

/**
 * Get detected number of integrity failures.
 *
 * @param cd crypt device handle (can be @e NULL)
 * @param name name of active device
 *
 * @return number of integrity failures or @e 0 otherwise
 *
 */
uint64_t crypt_get_active_integrity_failures(struct crypt_device *cd,
	const char *name);
/** @} */

/**
 * @defgroup crypt-pflags LUKS2 Device persistent flags and requirements
 * @addtogroup crypt-pflags
 * @{
 */

/**
 * LUKS2 header requirements
 */
/** Unfinished offline reencryption */
#define CRYPT_REQUIREMENT_OFFLINE_REENCRYPT	(UINT32_C(1) << 0)
/** Online reencryption in-progress */
#define CRYPT_REQUIREMENT_ONLINE_REENCRYPT	(UINT32_C(1) << 1)
/** Device configured with OPAL support */
#define CRYPT_REQUIREMENT_OPAL			(UINT32_C(1) << 2)
/** unknown requirement in header (output only) */
#define CRYPT_REQUIREMENT_UNKNOWN		(UINT32_C(1) << 31)

/**
 * Persistent flags type
 */
typedef enum {
	CRYPT_FLAGS_ACTIVATION, /**< activation flags, @see aflags */
	CRYPT_FLAGS_REQUIREMENTS /**< requirements flags */
} crypt_flags_type;

/**
 * Set persistent flags.
 *
 * @param cd crypt device handle (can be @e NULL)
 * @param type type to set (CRYPT_FLAGS_ACTIVATION or CRYPT_FLAGS_REQUIREMENTS)
 * @param flags flags to set
 *
 * @return @e 0 on success or negative errno value otherwise
 *
 * @note Valid only for LUKS2.
 *
 * @note Not all activation flags can be stored. Only ALLOW_DISCARD,
 * 	 SAME_CPU_CRYPT, SUBMIT_FROM_CRYPT_CPU and NO_JOURNAL can be
 * 	 stored persistently.
 *
 * @note Only requirements flags recognised by current library may be set.
 *	 CRYPT_REQUIREMENT_UNKNOWN is illegal (output only) in set operation.
 */
int crypt_persistent_flags_set(struct crypt_device *cd,
	crypt_flags_type type,
	uint32_t flags);

/**
 * Get persistent flags stored in header.
 *
 * @param cd crypt device handle (can be @e NULL)
 * @param type flags type to retrieve (CRYPT_FLAGS_ACTIVATION or CRYPT_FLAGS_REQUIREMENTS)
 * @param flags reference to output variable
 *
 * @return @e 0 on success or negative errno value otherwise
 */
int crypt_persistent_flags_get(struct crypt_device *cd,
	crypt_flags_type type,
	uint32_t *flags);
/** @} */

/**
 * @defgroup crypt-activation Device activation
 * @addtogroup crypt-activation
 * @{
 */

/**
 * Activate device or check using keyslot context. In some cases (device under
 * reencryption), more than one keyslot context is required (e.g. one for the old
 * volume key and one for the new volume key). The order of the keyslot
 * contexts does not matter. When less keyslot contexts are supplied than
 * required to unlock the device an -ESRCH error code is returned and you
 * should call the function again with an additional keyslot context specified.
 *
 * NOTE: the API at the moment fully works for single keyslot context only,
 * the additional keyslot context currently works only with
 * @e CRYPT_KC_TYPE_VK_KEYRING or @e CRYPT_KC_TYPE_KEY contexts.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check passphrase
 * @param keyslot requested keyslot to check or @e CRYPT_ANY_SLOT, keyslot is
 *        ignored for unlock methods not based on passphrase
 * @param kc keyslot context providing volume key or passphrase.
 * @param additional_keyslot requested additional keyslot to check or @e CRYPT_ANY_SLOT
 * @param additional_kc keyslot context providing additional volume key or
 *        passphrase (e.g. old volume key for device under reencryption).
 * @param flags activation flags
 *
 * @return unlocked key slot number for passphrase-based unlock, zero for other
 *         unlock methods (e.g. volume key context) or negative errno on error.
 */
int crypt_activate_by_keyslot_context(struct crypt_device *cd,
	const char *name,
	int keyslot,
	struct crypt_keyslot_context *kc,
	int additional_keyslot,
	struct crypt_keyslot_context *additional_kc,
	uint32_t flags);

/**
 * Activate device or check passphrase.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check passphrase
 * @param keyslot requested keyslot to check or @e CRYPT_ANY_SLOT
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of @e passphrase
 * @param flags activation flags
 *
 * @return unlocked key slot number or negative errno otherwise.
 */
int crypt_activate_by_passphrase(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *passphrase,
	size_t passphrase_size,
	uint32_t flags);

/**
 * Activate device or check using key file.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check keyfile
 * @param keyslot requested keyslot to check or CRYPT_ANY_SLOT
 * @param keyfile key file used to unlock volume key
 * @param keyfile_size number of bytes to read from keyfile, 0 is unlimited
 * @param keyfile_offset number of bytes to skip at start of keyfile
 * @param flags activation flags
 *
 * @return unlocked key slot number or negative errno otherwise.
 */
int crypt_activate_by_keyfile_device_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint64_t keyfile_offset,
	uint32_t flags);

/**
 * Backward compatible crypt_activate_by_keyfile_device_offset() (with size_t offset).
 */
int crypt_activate_by_keyfile_offset(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	size_t keyfile_offset,
	uint32_t flags);

/**
 * Backward compatible crypt_activate_by_keyfile_device_offset() (without offset).
 */
int crypt_activate_by_keyfile(struct crypt_device *cd,
	const char *name,
	int keyslot,
	const char *keyfile,
	size_t keyfile_size,
	uint32_t flags);

/**
 * Activate device using provided volume key.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check volume key
 * @param volume_key provided volume key (or @e NULL to use internal)
 * @param volume_key_size size of volume_key
 * @param flags activation flags
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note If @e NULL is used for volume_key, device has to be initialized
 * 	 by previous operation (like @ref crypt_format
 * 	 or @ref crypt_init_by_name)
 * @note For VERITY the volume key means root hash required for activation.
 * 	 Because kernel dm-verity is always read only, you have to provide
 * 	 CRYPT_ACTIVATE_READONLY flag always.
 * @note For TCRYPT the volume key should be always NULL
 * 	 the key from decrypted header is used instead.
 * @note For BITLK the name cannot be @e NULL checking volume key is not
 * 	 supported for BITLK, the device will be activated even if the
 * 	 provided key is not correct.
 */
int crypt_activate_by_volume_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	uint32_t flags);

/**
 * Activate VERITY device using provided key and optional signature).
 *
 * @param cd crypt device handle
 * @param name name of device to create
 * @param volume_key provided volume key
 * @param volume_key_size size of volume_key
 * @param signature buffer with signature for the key
 * @param signature_size bsize of signature buffer
 * @param flags activation flags
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note For VERITY the volume key means root hash required for activation.
 *	Because kernel dm-verity is always read only, you have to provide
 *	CRYPT_ACTIVATE_READONLY flag always.
 */
int crypt_activate_by_signed_key(struct crypt_device *cd,
	const char *name,
	const char *volume_key,
	size_t volume_key_size,
	const char *signature,
	size_t signature_size,
	uint32_t flags);

/**
 * Activate device using passphrase stored in kernel keyring.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check passphrase in keyring
 * @param key_description kernel keyring key description library should look
 *        for passphrase in
 * @param keyslot requested keyslot to check or CRYPT_ANY_SLOT
 * @param flags activation flags
 *
 * @return @e unlocked keyslot number on success or negative errno value otherwise.
 *
 * @note Keyslot passphrase must be stored in 'user' key type
 * 	 and the key has to be reachable for process context
 * 	 on behalf of which this function is called.
 */
int crypt_activate_by_keyring(struct crypt_device *cd,
	const char *name,
	const char *key_description,
	int keyslot,
	uint32_t flags);

/** lazy deactivation - remove once last user releases it */
#define CRYPT_DEACTIVATE_DEFERRED (UINT32_C(1) << 0)
/** force deactivation - if the device is busy, it is replaced by error device */
#define CRYPT_DEACTIVATE_FORCE    (UINT32_C(1) << 1)
/** if set, remove lazy deactivation */
#define CRYPT_DEACTIVATE_DEFERRED_CANCEL (UINT32_C(1) << 2)

/**
 * Deactivate crypt device. This function tries to remove active device-mapper
 * mapping from kernel. Also, sensitive data like the volume key are removed from
 * memory
 *
 * @param cd crypt device handle, can be @e NULL
 * @param name name of device to deactivate
 * @param flags deactivation flags
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_deactivate_by_name(struct crypt_device *cd,
	const char *name,
	uint32_t flags);

/**
 * Deactivate crypt device. See @ref crypt_deactivate_by_name with empty @e flags.
 */
int crypt_deactivate(struct crypt_device *cd, const char *name);
/** @} */

/**
 * @defgroup crypt-key Volume Key manipulation
 * @addtogroup crypt-key
 * @{
 */

/**
 * Get volume key from crypt device.
 *
 * @param cd crypt device handle
 * @param keyslot use this keyslot or @e CRYPT_ANY_SLOT
 * @param volume_key buffer for volume key
 * @param volume_key_size on input, size of buffer @e volume_key,
 *        on output size of @e volume_key
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of @e passphrase
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note For TCRYPT cipher chain is the volume key concatenated
 * 	 for all ciphers in chain.
 * @note For VERITY the volume key means root hash used for activation.
 * @note For LUKS devices, if passphrase is @e NULL and volume key is cached in
 * 	 device context it returns the volume key generated in preceding
 * 	 @link crypt_format @endlink call.
 */
int crypt_volume_key_get(struct crypt_device *cd,
	int keyslot,
	char *volume_key,
	size_t *volume_key_size,
	const char *passphrase,
	size_t passphrase_size);

/**
 * Get volume key from crypt device by keyslot context.
 *
 * @param cd crypt device handle
 * @param keyslot use this keyslot or @e CRYPT_ANY_SLOT
 * @param volume_key buffer for volume key
 * @param volume_key_size on input, size of buffer @e volume_key,
 *        on output size of @e volume_key
 * @param kc keyslot context used to unlock volume key
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note See @link crypt-keyslot-context-types @endlink for info on keyslot
 * 	 context initialization.
 * @note For TCRYPT cipher chain is the volume key concatenated
 * 	 for all ciphers in chain (kc may be NULL).
 * @note For VERITY the volume key means root hash used for activation
 * 	 (kc may be NULL).
 * @note For LUKS devices, if kc is @e NULL and volume key is cached in
 * 	 device context it returns the volume key generated in preceding
 * 	 @link crypt_format @endlink call.
 * @note @link CRYPT_KC_TYPE_TOKEN @endlink keyslot context is usable only with LUKS2 devices.
 * @note @link CRYPT_KC_TYPE_KEY @endlink keyslot context can not be used.
 * @note To get LUKS2 unbound key, keyslot parameter must not be @e CRYPT_ANY_SLOT.
 * @note EPERM errno means provided keyslot context could not unlock any (or selected)
 * 	 keyslot.
 * @note ENOENT errno means no LUKS keyslot is available to retrieve volume key from
 * 	 and there's no cached volume key in device handle.
 */
int crypt_volume_key_get_by_keyslot_context(struct crypt_device *cd,
	int keyslot,
	char *volume_key,
	size_t *volume_key_size,
	struct crypt_keyslot_context *kc);

/**
 * Verify that provided volume key is valid for crypt device.
 *
 * @param cd crypt device handle
 * @param volume_key provided volume key
 * @param volume_key_size size of @e volume_key
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note Negative EPERM return value means that passed volume_key
 * 	 did not pass digest verification routine (not a valid volume
 * 	 key).
 */
int crypt_volume_key_verify(struct crypt_device *cd,
	const char *volume_key,
	size_t volume_key_size);
/** @} */

/**
 * @defgroup crypt-devstat Crypt and Verity device status
 * @addtogroup crypt-devstat
 * @{
 */

/**
 * Device status
 */
typedef enum {
	CRYPT_INVALID,  /**< device mapping is invalid in this context */
	CRYPT_INACTIVE, /**< no such mapped device */
	CRYPT_ACTIVE,   /**< device is active */
	CRYPT_BUSY      /**< device is active and has open count > 0 */
} crypt_status_info;

/**
 * Get status info about device name.
 *
 * @param cd crypt device handle, can be @e NULL
 * @param name crypt device name
 *
 * @return value defined by crypt_status_info.
 *
 */
crypt_status_info crypt_status(struct crypt_device *cd, const char *name);

/**
 * Dump text-formatted information about crypt or verity device to log output.
 *
 * @param cd crypt device handle
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_dump(struct crypt_device *cd);

/**
 * Dump JSON-formatted information about LUKS2 device
 *
 * @param cd crypt device handle (only LUKS2 format supported)
 * @param json buffer with JSON, if NULL use log callback for output
 * @param flags dump flags (reserved)
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_dump_json(struct crypt_device *cd, const char **json, uint32_t flags);

/**
 * Get cipher used in device.
 *
 * @param cd crypt device handle
 *
 * @return used cipher, e.g. "aes" or @e NULL otherwise
 *
 */
const char *crypt_get_cipher(struct crypt_device *cd);

/**
 * Get cipher mode used in device.
 *
 * @param cd crypt device handle
 *
 * @return used cipher mode e.g. "xts-plain" or @e otherwise
 *
 */
const char *crypt_get_cipher_mode(struct crypt_device *cd);

/**
 * Get device UUID.
 *
 * @param cd crypt device handle
 *
 * @return device UUID or @e NULL if not set
 *
 */
const char *crypt_get_uuid(struct crypt_device *cd);

/**
 * Get path to underlying device.
 *
 * @param cd crypt device handle
 *
 * @return path to underlying device name
 *
 */
const char *crypt_get_device_name(struct crypt_device *cd);

/**
 * Get path to detached metadata device or @e NULL if it is not detached.
 *
 * @param cd crypt device handle
 *
 * @return path to underlying device name
 *
 */
const char *crypt_get_metadata_device_name(struct crypt_device *cd);

/**
 * Get device offset in 512-bytes sectors where real data starts (on underlying device).
 *
 * @param cd crypt device handle
 *
 * @return device offset in sectors
 *
 */
uint64_t crypt_get_data_offset(struct crypt_device *cd);

/**
 * Get IV offset in 512-bytes sectors (skip).
 *
 * @param cd crypt device handle
 *
 * @return IV offset
 *
 */
uint64_t crypt_get_iv_offset(struct crypt_device *cd);

/**
 * Get size (in bytes) of volume key for crypt device.
 *
 * @param cd crypt device handle
 *
 * @return volume key size
 *
 * @note For LUKS2, this function can be used only if there is at least
 *       one keyslot assigned to data segment.
 */
int crypt_get_volume_key_size(struct crypt_device *cd);

/**
 * Get size (in bytes) of encryption sector for crypt device.
 *
 * @param cd crypt device handle
 *
 * @return sector size
 *
 */
int crypt_get_sector_size(struct crypt_device *cd);

/**
 * Check if initialized LUKS context uses detached header
 * (LUKS header located on a different device than data.)
 *
 * @param cd crypt device handle
 *
 * @return @e 1 if detached header is used, @e 0 if not
 * or negative errno value otherwise.
 *
 * @note This is a runtime attribute, it does not say
 * 	 if a LUKS device requires detached header.
 * 	 This function works only with LUKS devices.
 */
int crypt_header_is_detached(struct crypt_device *cd);

/**
 * Get device parameters for VERITY device.
 *
 * @param cd crypt device handle
 * @param vp verity device info
 *
 * @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_get_verity_info(struct crypt_device *cd,
	struct crypt_params_verity *vp);

/**
 * Get device parameters for INTEGRITY device.
 *
 * @param cd crypt device handle
 * @param ip verity device info
 *
 * @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_get_integrity_info(struct crypt_device *cd,
	struct crypt_params_integrity *ip);
/** @} */

/**
 * @defgroup crypt-benchmark Benchmarking
 * Benchmarking of algorithms
 * @addtogroup crypt-benchmark
 * @{
 */

/**
 * Informational benchmark for ciphers.
 *
 * @param cd crypt device handle
 * @param cipher (e.g. "aes")
 * @param cipher_mode (e.g. "xts"), IV generator is ignored
 * @param volume_key_size size of volume key in bytes
 * @param iv_size size of IV in bytes
 * @param buffer_size size of encryption buffer in bytes used in test
 * @param encryption_mbs measured encryption speed in MiB/s
 * @param decryption_mbs measured decryption speed in MiB/s
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note If encryption_buffer_size is too small and encryption time
 *       cannot be properly measured, -ERANGE is returned.
 */
int crypt_benchmark(struct crypt_device *cd,
	const char *cipher,
	const char *cipher_mode,
	size_t volume_key_size,
	size_t iv_size,
	size_t buffer_size,
	double *encryption_mbs,
	double *decryption_mbs);

/**
 * Informational benchmark for PBKDF.
 *
 * @param cd crypt device handle
 * @param pbkdf PBKDF parameters
 * @param password password for benchmark
 * @param password_size size of password
 * @param salt salt for benchmark
 * @param salt_size size of salt
 * @param volume_key_size output volume key size
 * @param progress callback function
 * @param usrptr provided identification in callback
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_benchmark_pbkdf(struct crypt_device *cd,
	struct crypt_pbkdf_type *pbkdf,
	const char *password,
	size_t password_size,
	const char *salt,
	size_t salt_size,
	size_t volume_key_size,
	int (*progress)(uint32_t time_ms, void *usrptr),
	void *usrptr);
/** @} */

/**
 * @addtogroup crypt-keyslot
 * @{
 */

/**
 * Crypt keyslot info
 */
typedef enum {
	CRYPT_SLOT_INVALID,    /**< invalid keyslot */
	CRYPT_SLOT_INACTIVE,   /**< keyslot is inactive (free) */
	CRYPT_SLOT_ACTIVE,     /**< keyslot is active (used) */
	CRYPT_SLOT_ACTIVE_LAST,/**< keylost is active (used)
				 *  and last used at the same time */
	CRYPT_SLOT_UNBOUND     /**< keyslot is active and not bound
				 *  to any crypt segment (LUKS2 only) */
} crypt_keyslot_info;

/**
 * Get information about particular key slot.
 *
 * @param cd crypt device handle
 * @param keyslot requested keyslot to check or CRYPT_ANY_SLOT
 *
 * @return value defined by crypt_keyslot_info
 *
 */
crypt_keyslot_info crypt_keyslot_status(struct crypt_device *cd, int keyslot);

/**
 * Crypt keyslot priority
 */
typedef enum {
	CRYPT_SLOT_PRIORITY_INVALID =-1, /**< no such slot */
	CRYPT_SLOT_PRIORITY_IGNORE  = 0, /**< CRYPT_ANY_SLOT will ignore it for open */
	CRYPT_SLOT_PRIORITY_NORMAL  = 1, /**< default priority, tried after preferred */
	CRYPT_SLOT_PRIORITY_PREFER  = 2, /**< will try to open first */
} crypt_keyslot_priority;

/**
 * Get keyslot priority (LUKS2)
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number
 *
 * @return value defined by crypt_keyslot_priority
 */
crypt_keyslot_priority crypt_keyslot_get_priority(struct crypt_device *cd, int keyslot);

/**
 * Set keyslot priority (LUKS2)
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number
 * @param priority priority defined in crypt_keyslot_priority
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_keyslot_set_priority(struct crypt_device *cd, int keyslot, crypt_keyslot_priority priority);

/**
 * Get number of keyslots supported for device type.
 *
 * @param type crypt device type
 *
 * @return slot count or negative errno otherwise if device
 * doesn't not support keyslots.
 */
int crypt_keyslot_max(const char *type);

/**
 * Get keyslot area pointers (relative to metadata device).
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number
 * @param offset offset on metadata device (in bytes)
 * @param length length of keyslot area (in bytes)
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_keyslot_area(struct crypt_device *cd,
	int keyslot,
	uint64_t *offset,
	uint64_t *length);

/**
 * Get size (in bytes) of stored key in particular keyslot.
 * Use for LUKS2 unbound keyslots, for other keyslots it is the same as @ref crypt_get_volume_key_size
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number
 *
 * @return volume key size or negative errno value otherwise.
 *
 */
int crypt_keyslot_get_key_size(struct crypt_device *cd, int keyslot);

/**
 * Get cipher and key size for keyslot encryption.
 * Use for LUKS2 keyslot to set different encryption type than for data encryption.
 * Parameters will be used for next keyslot operations.
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number of CRYPT_ANY_SLOT for default
 * @param key_size encryption key size (in bytes)
 *
 * @return cipher specification on success or @e NULL.
 *
 * @note This is the encryption of keyslot itself, not the data encryption algorithm!
 */
const char *crypt_keyslot_get_encryption(struct crypt_device *cd, int keyslot, size_t *key_size);

/**
 * Get PBKDF parameters for keyslot.
 *
 * @param cd crypt device handle
 * @param keyslot keyslot number
 * @param pbkdf struct with returned PBKDF parameters
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_keyslot_get_pbkdf(struct crypt_device *cd, int keyslot, struct crypt_pbkdf_type *pbkdf);

/**
 * Set encryption for keyslot.
 * Use for LUKS2 keyslot to set different encryption type than for data encryption.
 * Parameters will be used for next keyslot operations that create or change a keyslot.
 *
 * @param cd crypt device handle
 * @param cipher (e.g. "aes-xts-plain64")
 * @param key_size encryption key size (in bytes)
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note To reset to default keyslot encryption (the same as for data)
 *       set cipher to NULL and key size to 0.
 */
int crypt_keyslot_set_encryption(struct crypt_device *cd,
	const char *cipher,
	size_t key_size);

/**
 * Get directory where mapped crypt devices are created
 *
 * @return the directory path
 */
const char *crypt_get_dir(void);

/** @} */

/**
 * @defgroup crypt-backup Device metadata backup
 * @addtogroup crypt-backup
 * @{
 */
/**
 * Backup header and keyslots to file.
 *
 * @param cd crypt device handle
 * @param requested_type @link crypt-type @endlink or @e NULL for all known
 * @param backup_file file to backup header to
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_header_backup(struct crypt_device *cd,
	const char *requested_type,
	const char *backup_file);

/**
 * Restore header and keyslots from backup file.
 *
 * @param cd crypt device handle
 * @param requested_type @link crypt-type @endlink or @e NULL for all known
 * @param backup_file file to restore header from
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 */
int crypt_header_restore(struct crypt_device *cd,
	const char *requested_type,
	const char *backup_file);
/** @} */

/**
 * @defgroup crypt-dbg Library debug level
 * Set library debug level
 * @addtogroup crypt-dbg
 * @{
 */

/** Debug all */
#define CRYPT_DEBUG_ALL  -1
/** Debug all with additional JSON dump (for LUKS2) */
#define CRYPT_DEBUG_JSON  -2
/** Debug none */
#define CRYPT_DEBUG_NONE  0

/**
 * Set the debug level for library
 *
 * @param level debug level
 *
 */
void crypt_set_debug_level(int level);
/** @} */

/**
 * @defgroup crypt-keyfile Function to read keyfile
 * @addtogroup crypt-keyfile
 * @{
 */

/**
 * Read keyfile
 *
 * @param cd crypt device handle
 * @param keyfile keyfile to read
 * @param key buffer for key
 * @param key_size_read size of read key
 * @param keyfile_offset key offset in keyfile
 * @param key_size exact key length to read from file or 0
 * @param flags keyfile read flags
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note If key_size is set to zero we read internal max length
 * 	 and actual size read is returned via key_size_read parameter.
 */
int crypt_keyfile_device_read(struct crypt_device *cd,
	const char *keyfile,
	char **key, size_t *key_size_read,
	uint64_t keyfile_offset,
	size_t key_size,
	uint32_t flags);

/**
 * Backward compatible crypt_keyfile_device_read() (with size_t offset).
 */
int crypt_keyfile_read(struct crypt_device *cd,
	const char *keyfile,
	char **key, size_t *key_size_read,
	size_t keyfile_offset,
	size_t key_size,
	uint32_t flags);

/** Read key only to the first end of line (\\n). */
#define CRYPT_KEYFILE_STOP_EOL   (UINT32_C(1) << 0)
/** @} */

/**
 * @defgroup crypt-wipe Function to wipe device
 * @addtogroup crypt-wipe
 * @{
 */
/**
 * Wipe pattern
 */
typedef enum {
	CRYPT_WIPE_ZERO,           /**< Fill with zeroes */
	CRYPT_WIPE_RANDOM,         /**< Use RNG to fill data */
	CRYPT_WIPE_ENCRYPTED_ZERO, /**< Obsolete, same as CRYPT_WIPE_RANDOM */
	CRYPT_WIPE_SPECIAL,        /**< Compatibility only, do not use (Gutmann method) */
} crypt_wipe_pattern;

/**
 * Wipe/Fill (part of) a device with the selected pattern.
 *
 * @param cd crypt device handle
 * @param dev_path path to device to wipe or @e NULL if data device should be used
 * @param pattern selected wipe pattern
 * @param offset offset on device (in bytes)
 * @param length length of area to be wiped (in bytes)
 * @param wipe_block_size used block for wiping (one step) (in bytes)
 * @param flags wipe flags
 * @param progress callback function called after each @e wipe_block_size or @e NULL
 * @param usrptr provided identification in callback
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note A @e progress callback can interrupt wipe process by returning non-zero code.
 *
 * @note If the error values is -EIO or -EINTR, some part of the device could
 *       be overwritten. Other error codes (-EINVAL, -ENOMEM) means that no IO was performed.
 */
int crypt_wipe(struct crypt_device *cd,
	const char *dev_path, /* if null, use data device */
	crypt_wipe_pattern pattern,
	uint64_t offset,
	uint64_t length,
	size_t wipe_block_size,
	uint32_t flags,
	int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
	void *usrptr
);

/** Use direct-io */
#define CRYPT_WIPE_NO_DIRECT_IO (UINT32_C(1) << 0)

enum {
	CRYPT_LUKS2_SEGMENT = -2,
	CRYPT_NO_SEGMENT = -1,
};

/**
 * Safe erase of a partition or an entire OPAL device. WARNING: ALL DATA ON
 * PARTITION/DISK WILL BE LOST. If the CRYPT_NO_SEGMENT is passed as the segment
 * parameter, the entire device will be wiped, not just what is included in the
 * LUKS2 device/partition.
 *
 * @param cd crypt device handle
 * @param segment the segment number to wipe (0..8), or CRYPT_LUKS2_SEGMENT
 *        to wipe the segment configured in the LUKS2 header, or CRYPT_NO_SEGMENT
 *        to wipe the entire device via a factory reset.
 * @param password admin password/PSID (for factory reset) to wipe the
 *        partition/device
 * @param password_size length of password/PSID
 * @param flags (currently unused)
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_wipe_hw_opal(struct crypt_device *cd,
	int segment, /* 0..8, CRYPT_LUKS2_SEGMENT -2, CRYPT_NO_SEGMENT -1 */
	const char *password, /* Admin1 PIN or PSID */
	size_t password_size,
	uint32_t flags /* currently unused */
);

/** @} */

/**
 * @defgroup crypt-tokens LUKS2 token wrapper access
 *
 * Utilities for handling tokens LUKS2
 * Token is a device or a method how to read password for particular keyslot
 * automatically. It can be chunk of data stored on hardware token or
 * just a metadata how to generate the password.
 *
 * @addtogroup crypt-tokens
 * @{
 */

/**
 * Get number of tokens supported for device type.
 *
 * @param type crypt device type
 *
 * @return token count or negative errno otherwise if device
 * doesn't not support tokens.
 *
 * @note Real number of supported tokens for a particular device depends
 *       on usable metadata area size.
 */
int crypt_token_max(const char *type);

/** Iterate through all tokens */
#define CRYPT_ANY_TOKEN -1

/**
 * Get content of a token definition in JSON format.
 *
 * @param cd crypt device handle
 * @param token token id
 * @param json buffer with JSON
 *
 * @return allocated token id or negative errno otherwise.
 */
int crypt_token_json_get(struct crypt_device *cd,
	int token,
	const char **json);

/**
 * Store content of a token definition in JSON format.
 *
 * @param cd crypt device handle
 * @param token token id or @e CRYPT_ANY_TOKEN to allocate new one
 * @param json buffer with JSON or @e NULL to remove token
 *
 * @return allocated token id or negative errno otherwise.
 *
 * @note The buffer must be in proper JSON format and must contain at least
 *       string "type" with slot type and an array of string names "keyslots".
 *       Keyslots array contains assignments to particular slots and can be empty.
 */
int crypt_token_json_set(struct crypt_device *cd,
	int token,
	const char *json);

/**
 * Token info
 */
typedef enum {
	CRYPT_TOKEN_INVALID,          /**< token is invalid */
	CRYPT_TOKEN_INACTIVE,         /**< token is empty (free) */
	CRYPT_TOKEN_INTERNAL,         /**< active internal token with driver */
	CRYPT_TOKEN_INTERNAL_UNKNOWN, /**< active internal token (reserved name) with missing token driver */
	CRYPT_TOKEN_EXTERNAL,         /**< active external (user defined) token with driver */
	CRYPT_TOKEN_EXTERNAL_UNKNOWN, /**< active external (user defined) token with missing token driver */
} crypt_token_info;

/**
 * Get info for specific token.
 *
 * @param cd crypt device handle
 * @param token existing token id
 * @param type pointer for returned type string
 *
 * @return token status info. For any returned status (besides CRYPT_TOKEN_INVALID
 * 	   and CRYPT_TOKEN_INACTIVE) and if type parameter is not NULL it will
 * 	   contain address of type string.
 *
 * @note if required, create a copy of string referenced in *type before calling next
 * 	 libcryptsetup API function. The reference may become invalid.
 */
crypt_token_info crypt_token_status(struct crypt_device *cd, int token, const char **type);

/**
 * LUKS2 keyring token parameters.
 *
 * @see crypt_token_builtin_set
 *
 */
struct crypt_token_params_luks2_keyring {
	const char *key_description; /**< Reference in keyring */
};

/**
 * Create a new luks2 keyring token.
 *
 * @param cd crypt device handle
 * @param token token id or @e CRYPT_ANY_TOKEN to allocate new one
 * @param params luks2 keyring token params
 *
 * @return allocated token id or negative errno otherwise.
 *
 */
int crypt_token_luks2_keyring_set(struct crypt_device *cd,
	int token,
	const struct crypt_token_params_luks2_keyring *params);

/**
 * Get LUKS2 keyring token params
 *
 * @param cd crypt device handle
 * @param token existing luks2 keyring token id
 * @param params returned luks2 keyring token params
 *
 * @return allocated token id or negative errno otherwise.
 *
 * @note do not call free() on params members. Members are valid only
 * 	 until next libcryptsetup function is called.
 */
int crypt_token_luks2_keyring_get(struct crypt_device *cd,
	int token,
	struct crypt_token_params_luks2_keyring *params);

/**
 * Assign a token to particular keyslot.
 * (There can be more keyslots assigned to one token id.)
 *
 * @param cd crypt device handle
 * @param token specific token id
 * @param keyslot keyslot to be assigned to token (CRYPT_ANY SLOT
 * 	  assigns all active keyslots to token)
 *
 * @return requested token id to be assigned or negative errno otherwise.
 */
int crypt_token_assign_keyslot(struct crypt_device *cd,
	int token,
	int keyslot);

/**
 * Unassign a token from particular keyslot.
 * (There can be more keyslots assigned to one token id.)
 *
 * @param cd crypt device handle
 * @param token specific token id
 * @param keyslot keyslot to be unassigned from token (CRYPT_ANY SLOT
 * 	  unassigns all active keyslots from token)
 *
 * @return requested token id to be unassigned or negative errno otherwise.
 */
int crypt_token_unassign_keyslot(struct crypt_device *cd,
	int token,
	int keyslot);

/**
 * Get info about token assignment to particular keyslot.
 *
 * @param cd crypt device handle
 * @param token token id
 * @param keyslot keyslot
 *
 * @return 0 on success (token exists and is assigned to the keyslot),
 *	   -ENOENT if token is not assigned to a keyslot (token, keyslot
 *	   or both may be inactive) or other negative errno otherwise.
 */
int crypt_token_is_assigned(struct crypt_device *cd,
	int token,
	int keyslot);

/**
 * Token handler open function prototype.
 * This function retrieves password from a token and return allocated buffer
 * containing this password. This buffer has to be deallocated by calling
 * free() function and content should be wiped before deallocation.
 *
 * @param cd crypt device handle
 * @param token token id
 * @param buffer returned allocated buffer with password
 * @param buffer_len length of the buffer
 * @param usrptr user data in @link crypt_activate_by_token @endlink
 *
 * @return 0 on success (token passed LUKS2 keyslot passphrase in buffer) or
 *         negative errno otherwise.
 *
 * @note Negative ENOANO errno means that token is PIN protected and caller should
 *       use @link crypt_activate_by_token_pin @endlink with PIN provided.
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system.
 */
typedef int (*crypt_token_open_func) (
	struct crypt_device *cd,
	int token,
	char **buffer,
	size_t *buffer_len,
	void *usrptr);

/**
 * Token handler open with passphrase/PIN function prototype.
 * This function retrieves password from a token and return allocated buffer
 * containing this password. This buffer has to be deallocated by calling
 * free() function and content should be wiped before deallocation.
 *
 * @param cd crypt device handle
 * @param token token id
 * @param pin passphrase (or PIN) to unlock token (may be binary data)
 * @param pin_size size of @e pin
 * @param buffer returned allocated buffer with password
 * @param buffer_len length of the buffer
 * @param usrptr user data in @link crypt_activate_by_token @endlink
 *
 * @return 0 on success (token passed LUKS2 keyslot passphrase in buffer) or
 *         negative errno otherwise.
 *
 * @note Negative ENOANO errno means that token is PIN protected and PIN was
 *       missing or wrong.
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system.
 */
typedef int (*crypt_token_open_pin_func) (
	struct crypt_device *cd,
	int token,
	const char *pin,
	size_t pin_size,
	char **buffer,
	size_t *buffer_len,
	void *usrptr);

/**
 * Token handler buffer free function prototype.
 * This function is used by library to free the buffer with keyslot
 * passphrase when it's no longer needed. If not defined the library
 * overwrites buffer with zeroes and call free().
 *
 * @param buffer the buffer with keyslot passphrase
 * @param buffer_len the buffer length
 */
typedef void (*crypt_token_buffer_free_func) (void *buffer, size_t buffer_len);

/**
 * Token handler validate function prototype.
 * This function validates JSON representation of user defined token for additional data
 * specific for its token type. If defined in the handler, it's called
 * during @link crypt_activate_by_token @endlink. It may also be called during
 * @link crypt_token_json_set @endlink when appropriate token handler was registered before
 * with @link crypt_token_register @endlink.
 *
 * @param cd crypt device handle
 * @param json buffer with JSON
 */
typedef int (*crypt_token_validate_func) (struct crypt_device *cd, const char *json);

/**
 * Token handler dump function prototype.
 * This function is supposed to print token implementation specific details. It gets
 * called during @link crypt_dump @endlink if token handler was registered before.
 *
 * @param cd crypt device handle
 * @param json buffer with token JSON
 *
 * @note dump implementations are advised to use @link crypt_log @endlink function
 *	 to dump token details.
 */
typedef void (*crypt_token_dump_func) (struct crypt_device *cd, const char *json);

/**
 * Token handler version function prototype.
 * This function is supposed to return pointer to version string information.
 *
 * @note The returned string is advised to contain only version.
 *	 For example '1.0.0' or 'v1.2.3.4'.
 *
 */
typedef const char * (*crypt_token_version_func) (void);

/**
 * Token handler
 */
typedef struct  {
	const char *name;           /**< token handler name */
	crypt_token_open_func open; /**< token handler open function */
	crypt_token_buffer_free_func buffer_free; /**< token handler buffer_free function (optional) */
	crypt_token_validate_func validate; /**< token handler validate function (optional) */
	crypt_token_dump_func dump; /**< token handler dump function (optional) */
} crypt_token_handler;

/**
 * Register token handler
 *
 * @param handler token handler to register
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_token_register(const crypt_token_handler *handler);

/**
 * Report configured path where library searches for external token handlers
 *
 * @return @e absolute path when external tokens are enabled or @e NULL otherwise.
 */
const char *crypt_token_external_path(void);

/**
 * Override configured external token handlers path for the library.
 *
 * @param path Absolute path (starts with '/') to new external token handlers directory or @e NULL.
 *
 * @note if @e path is @e NULL the external token path is reset to default path.
 *
 * @return @e 0 on success or negative errno value otherwise.
 */
int crypt_token_set_external_path(const char *path);

/**
 * Disable external token handlers (plugins) support
 * If disabled, it cannot be enabled again.
 */
void crypt_token_external_disable(void);

/** ABI version for external token in libcryptsetup-token-[name].so */
#define CRYPT_TOKEN_ABI_VERSION1    "CRYPTSETUP_TOKEN_1.0"

/** open by token - ABI exported symbol for external token (mandatory) */
#define CRYPT_TOKEN_ABI_OPEN        "cryptsetup_token_open"
/** open by token with PIN - ABI exported symbol for external token */
#define CRYPT_TOKEN_ABI_OPEN_PIN    "cryptsetup_token_open_pin"
/** deallocate callback - ABI exported symbol for external token */
#define CRYPT_TOKEN_ABI_BUFFER_FREE "cryptsetup_token_buffer_free"
/** validate token metadata - ABI exported symbol for external token */
#define CRYPT_TOKEN_ABI_VALIDATE    "cryptsetup_token_validate"
/** dump token metadata - ABI exported symbol for external token */
#define CRYPT_TOKEN_ABI_DUMP        "cryptsetup_token_dump"
/** token version - ABI exported symbol for external token */
#define CRYPT_TOKEN_ABI_VERSION     "cryptsetup_token_version"

/**
 * Activate device or check key using a token.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check token
 * @param token requested token to check or CRYPT_ANY_TOKEN to check all
 * @param usrptr provided identification in callback
 * @param flags activation flags
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note EPERM errno means token provided passphrase successfully, but
 *       passphrase did not unlock any keyslot associated with the token.
 *
 * @note ENOENT errno means no token (or subsequently assigned keyslot) was
 *       eligible to unlock device.
 *
 * @note ENOANO errno means that token is PIN protected and you should call
 *       @link crypt_activate_by_token_pin @endlink with PIN
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system.
 *
 * @note with @e token set to CRYPT_ANY_TOKEN libcryptsetup runs best effort loop
 *       to unlock device using any available token. It may happen that various token handlers
 *       return different error codes. At the end loop returns error codes in the following
 *       order (from the most significant to the least) any negative errno except those
 *       listed below, non negative token id (success), -ENOANO, -EAGAIN, -EPERM, -ENOENT.
 */
int crypt_activate_by_token(struct crypt_device *cd,
	const char *name,
	int token,
	void *usrptr,
	uint32_t flags);

/**
 * Activate device or check key using a token with PIN.
 *
 * @param cd crypt device handle
 * @param name name of device to create, if @e NULL only check token
 * @param type restrict type of token, if @e NULL all types are allowed
 * @param token requested token to check or CRYPT_ANY_TOKEN to check all
 * @param pin passphrase (or PIN) to unlock token (may be binary data)
 * @param pin_size size of @e pin
 * @param usrptr provided identification in callback
 * @param flags activation flags
 *
 * @return unlocked key slot number or negative errno otherwise.
 *
 * @note EPERM errno means token provided passphrase successfully, but
 *       passphrase did not unlock any keyslot associated with the token.
 *
 * @note ENOENT errno means no token (or subsequently assigned keyslot) was
 *       eligible to unlock device.
 *
 * @note ENOANO errno means that token is PIN protected and was either missing
 *       (NULL) or wrong.
 *
 * @note Negative EAGAIN errno means token handler requires additional hardware
 *       not present in the system.
 *
 * @note with @e token set to CRYPT_ANY_TOKEN libcryptsetup runs best effort loop
 *       to unlock device using any available token. It may happen that various token handlers
 *       return different error codes. At the end loop returns error codes in the following
 *       order (from the most significant to the least) any negative errno except those
 *       listed below, non negative token id (success), -ENOANO, -EAGAIN, -EPERM, -ENOENT.
 */
int crypt_activate_by_token_pin(struct crypt_device *cd,
	const char *name,
	const char *type,
	int token,
	const char *pin,
	size_t pin_size,
	void *usrptr,
	uint32_t flags);
/** @} */

/**
 * @defgroup crypt-reencryption LUKS2 volume reencryption support
 *
 * Set of functions to handling LUKS2 volume reencryption
 *
 * @addtogroup crypt-reencryption
 * @{
 */

/** Initialize reencryption metadata but do not run reencryption yet. (in) */
#define CRYPT_REENCRYPT_INITIALIZE_ONLY    (UINT32_C(1) << 0)
/** Move the first segment, used only with datashift resilience mode
 *  and subvariants. (in/out) */
#define CRYPT_REENCRYPT_MOVE_FIRST_SEGMENT (UINT32_C(1) << 1)
/** Resume already initialized reencryption only. (in) */
#define CRYPT_REENCRYPT_RESUME_ONLY        (UINT32_C(1) << 2)
/** Run reencryption recovery only. (in) */
#define CRYPT_REENCRYPT_RECOVERY           (UINT32_C(1) << 3)
/** Reencryption requires metadata protection. (in/out) */
#define CRYPT_REENCRYPT_REPAIR_NEEDED      (UINT32_C(1) << 4)

/**
 * Reencryption direction
 */
typedef enum {
	CRYPT_REENCRYPT_FORWARD = 0, /**< forward direction */
	CRYPT_REENCRYPT_BACKWARD     /**< backward direction */
} crypt_reencrypt_direction_info;

/**
 * Reencryption mode
 */
typedef enum {
	CRYPT_REENCRYPT_REENCRYPT = 0, /**< Reencryption mode */
	CRYPT_REENCRYPT_ENCRYPT,       /**< Encryption mode */
	CRYPT_REENCRYPT_DECRYPT,       /**< Decryption mode */
} crypt_reencrypt_mode_info;

/**
 * LUKS2 reencryption options.
 */
struct crypt_params_reencrypt {
	crypt_reencrypt_mode_info mode;           /**< Reencryption mode, immutable after first init. */
	crypt_reencrypt_direction_info direction; /**< Reencryption direction, immutable after first init. */
	const char *resilience;                   /**< Resilience mode: "none", "checksum", "journal", "datashift",
						       "datashift-checksum" or "datashift-journal".
						       "datashift" mode is immutable, "datashift-" subvariant can be only
						       changed to other "datashift-" subvariant */
	const char *hash;                         /**< Used hash for "checksum" resilience type, ignored otherwise. */
	uint64_t data_shift;                      /**< Used in "datashift" mode (and subvariants), must be non-zero,
						       immutable after first init. */
	uint64_t max_hotzone_size;                /**< Maximum hotzone size (may be lowered by library). For "datashift-" subvariants
						       it is used to set size of moved segment (decryption only). */
	uint64_t device_size;			  /**< Reencrypt only initial part of the data device. */
	const struct crypt_params_luks2 *luks2;   /**< LUKS2 parameters for the final reencryption volume.*/
	uint32_t flags;                           /**< Reencryption flags. */
};

/**
 * Initialize reencryption metadata using passphrase.
 *
 * This function initializes on-disk metadata to include all reencryption segments,
 * according to the provided options.
 * If metadata already contains ongoing reencryption metadata, it loads these parameters
 * (in this situation all parameters except @e name and @e passphrase can be omitted).
 *
 * @param cd crypt device handle
 * @param name name of active device or @e NULL for offline reencryption
 * @param passphrase passphrase used to unlock volume key
 * @param passphrase_size size of @e passphrase (binary data)
 * @param keyslot_old keyslot to unlock existing device or CRYPT_ANY_SLOT
 * @param keyslot_new existing (unbound) reencryption keyslot; must be set except for decryption
 * @param cipher cipher specification (e.g. "aes")
 * @param cipher_mode cipher mode and IV (e.g. "xts-plain64")
 * @param params reencryption parameters @link crypt_params_reencrypt @endlink.
 *
 * @return reencryption key slot number or negative errno otherwise.
 */
int crypt_reencrypt_init_by_passphrase(struct crypt_device *cd,
	const char *name,
	const char *passphrase,
	size_t passphrase_size,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params);

/**
 * Initialize reencryption metadata using passphrase in keyring.
 *
 * This function initializes on-disk metadata to include all reencryption segments,
 * according to the provided options.
 * If metadata already contains ongoing reencryption metadata, it loads these parameters
 * (in this situation all parameters except @e name and @e key_description can be omitted).
 *
 * @param cd crypt device handle
 * @param name name of active device or @e NULL for offline reencryption
 * @param key_description passphrase (key) identification in keyring
 * @param keyslot_old keyslot to unlock existing device or CRYPT_ANY_SLOT
 * @param keyslot_new existing (unbound) reencryption keyslot; must be set except for decryption
 * @param cipher cipher specification (e.g. "aes")
 * @param cipher_mode cipher mode and IV (e.g. "xts-plain64")
 * @param params reencryption parameters @link crypt_params_reencrypt @endlink.
 *
 * @return reencryption key slot number or negative errno otherwise.
 */
int crypt_reencrypt_init_by_keyring(struct crypt_device *cd,
	const char *name,
	const char *key_description,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params);

/**
 *
 * Initialize or reload LUKS2 reencryption operation using keyslot contexts.
 *
 * The function can initialize reencryption on-disk metadata or reload reencryption
 * context from on-disk LUSK2 metadata to resume interrupted operation.
 *
 * If the device is not in reencryption state (@link crypt_reencrypt_status @endlink
 * returns @link CRYPT_REENCRYPT_NONE @endlink) the function initializes on-disk
 * metadata to include all necessary reencryption segments and new encryption
 * parameters (cipher, cipher mode, encryption sector size) according to the
 * provided parameters.
 *
 * If on-disk metadata already describes reencryption operation
 * (@link crypt_reencrypt_status @endlink returns @link CRYPT_REENCRYPT_CLEAN @endlink),
 * it loads these parameters and internally initializes reencryption context. It also verifies
 * if the device is eligible to resume reencryption operation. Some reencryption parameters
 * (@link crypt_params_reencrypt @endlink) may be modified depending on the original values in
 * the initialization call. When resuming the operation, all parameters may be omitted except
 * @e cd, @e name (offline/online),@e kc_old and @e kc_new.
 *
 * If on-disk metadata describes reencryption operation requiring recovery
 * (@link crypt_reencrypt_status @endlink returns @link CRYPT_REENCRYPT_CRASH @endlink),
 * it can be recovered by adding @link CRYPT_REENCRYPT_RECOVERY @endlink flag in @link
 * crypt_params_reencrypt @endlink parameter.
 *
 * @param cd crypt device handle
 * @param name name of the active device or @e NULL for offline reencryption
 * @param kc_old keyslot context providing access to volume key in keyslot id @e keyslot_old.
 * @param kc_new keyslot context providing access to volume key in keyslot id @e keyslot_new.
 * @param keyslot_old keyslot id containing current volume key for the device or CRYPT_ANY_SLOT
 * @param keyslot_new keyslot id containing (unbound) future volume key in encryption or reencryption
 *        operation. It must be set in the initialization call except when initializing the decrypt
 *        operation. In reencryption operation it may contain also the current volume key in case the
 *        volume key change is not requested.
 * @param cipher new cipher specification (e.g. "aes") or @e NULL in decryption. Relevant only
 * 	  during metadata initialization.
 * @param cipher_mode cipher mode and IV (e.g. "xts-plain64") or @e NULL in decryption.
 * 	  Relevant only during metadata initialization.
 * @param params reencryption parameters @link crypt_params_reencrypt @endlink.
 *
 * @return reencryption key slot number or negative errno otherwise.
 *
 * @note Only after successful reencryption initialization you may run the operation with
 * 	 @link crypt_reencrypt_run @endlink.
 *
 * @note During @link CRYPT_REENCRYPT_REENCRYPT @endlink operation it is highly recommended
 * 	 to use same keyslot context (same passphrase, token, keyfile, etc) in both @e kc_old
 * 	 and @e kc_new parameters for at least one keyslot containing future volume key and one
 * 	 keyslot containing current volume key. If the same keyslot context can not be used
 * 	 to unlock any current or any future volume key it would be impossible to perform reencryption
 * 	 crash recovery during device activation for example after system reboot. Any keyslot
 * 	 passphrase may be changed in-before initializing reencryption operation via @link
 * 	 crypt_keyslot_change_by_passphrase @endlink.
 */
int crypt_reencrypt_init_by_keyslot_context(struct crypt_device *cd,
	const char *name,
	struct crypt_keyslot_context *kc_old,
	struct crypt_keyslot_context *kc_new,
	int keyslot_old,
	int keyslot_new,
	const char *cipher,
	const char *cipher_mode,
	const struct crypt_params_reencrypt *params);

/**
 * Legacy data reencryption function.
 *
 * @param cd crypt device handle
 * @param progress is a callback function reporting device \b size,
 * current \b offset of reencryption and provided \b usrptr identification
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @deprecated Use @link crypt_reencrypt_run @endlink instead.
 */
int crypt_reencrypt(struct crypt_device *cd,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr))
__attribute__((deprecated));

/**
 * Run data reencryption.
 *
 * @param cd crypt device handle
 * @param progress is a callback function reporting device \b size,
 * current \b offset of reencryption and provided \b usrptr identification
 * @param usrptr progress specific data
 *
 * @return @e 0 on success or negative errno value otherwise.
 *
 * @note A @e progress callback can interrupt reencryption process by returning non-zero code.
 */
int crypt_reencrypt_run(struct crypt_device *cd,
		    int (*progress)(uint64_t size, uint64_t offset, void *usrptr),
		    void *usrptr);

/**
 * Reencryption status info
 */
typedef enum {
	CRYPT_REENCRYPT_NONE = 0, /**< No reencryption in progress */
	CRYPT_REENCRYPT_CLEAN,    /**< Ongoing reencryption in a clean state. */
	CRYPT_REENCRYPT_CRASH,    /**< Aborted reencryption that need internal recovery. */
	CRYPT_REENCRYPT_INVALID   /**< Invalid state. */
} crypt_reencrypt_info;

/**
 * LUKS2 reencryption status.
 *
 * @param cd crypt device handle
 * @param params reencryption parameters
 *
 * @return reencryption status info and parameters.
 */
crypt_reencrypt_info crypt_reencrypt_status(struct crypt_device *cd,
		struct crypt_params_reencrypt *params);
/** @} */

/**
 * @defgroup crypt-memory Safe memory helpers functions
 * @addtogroup crypt-memory
 * @{
 */

/**
 * Allocate safe memory (content is safely wiped on deallocation).
 *
 * @param size size of memory in bytes
 *
 * @return pointer to allocated memory or @e NULL.
 */
void *crypt_safe_alloc(size_t size);

/**
 * Release safe memory, content is safely wiped.
 * The pointer must be allocated with @link crypt_safe_alloc @endlink
 *
 * @param data pointer to memory to be deallocated
 */
void crypt_safe_free(void *data);

/**
 * Reallocate safe memory (content is copied and safely wiped on deallocation).
 *
 * @param data pointer to memory to be deallocated
 * @param size new size of memory in bytes
 *
 * @return pointer to allocated memory or @e NULL.
 */
void *crypt_safe_realloc(void *data, size_t size);

/**
 * Safe clear memory area (compile should not compile this call out).
 *
 * @param data pointer to memory to be cleared
 * @param size size of memory in bytes
 */
void crypt_safe_memzero(void *data, size_t size);

/**
 * Memcpy helper to avoid spilling sensitive data through additional registers
 *
 * @param dst pointer to memory to be written
 * @param src pointer to memory to be copied
 * @param size size of memory in bytes
 */
void *crypt_safe_memcpy(void *dst, const void *src, size_t size);

/** @} */

/**
 * @defgroup crypt-keyring Kernel keyring manipulation
 * @addtogroup crypt-keyring
 * @{
 */

/**
 * Link the volume key to the specified kernel keyring.
 *
 * The volume can have one or two keys. Normally, the device has one key.
 * However if reencryption was started and not finished yet, the volume will
 * have two volume keys (the new VK for the already reencrypted segment and old
 * VK for the not yet reencrypted segment).
 *
 * The @e old_key_description argument is required only for
 * devices that are in re-encryption and have two volume keys at the same time
 * (old and new). You can set the @e old_key_description to NULL,
 * but if you supply number of keys less than required, the function will
 * return -ESRCH.  In that case you need to call the function again and set
 * the missing key description. When supplying just one key description, make
 * sure to supply it in the @e key_description.
 *
 * @param cd crypt device handle
 * @param key_description the key description of the volume key linked in desired keyring.
 * @param old_key_description the key description of the old volume key linked in desired keyring
 *	  (for devices in re-encryption).
 * @param key_type_desc the key type used for the volume key. Currently only "user" and "logon" types are
 *	  supported. if @e NULL is specified the default "user" type is applied.
 * @param keyring_to_link_vk the keyring description of the keyring in which volume key should
 *	  be linked, if @e NULL is specified, linking will be disabled.
 *
 * @note keyring_to_link_vk may be passed in various string formats:
 * 	 It can be kernel key numeric id of existing keyring written as a string,
 * 	 keyring name prefixed by either "%:" or "%keyring:" substrings or keyctl
 * 	 special values for keyrings "@t", "@p", "@s" and so on. See keyctl(1) man page,
 * 	 section KEY IDENTIFIERS for more information. All other prefixes starting "%<type>:"
 * 	 are ignored.
 *
 * @note key_description "%<type>:" prefixes are ignored. Type is applied based on key_type parameter
 * 	 value.
 */
int crypt_set_keyring_to_link(struct crypt_device* cd,
	const char* key_description,
	const char* old_key_description,
	const char* key_type_desc,
	const char* keyring_to_link_vk);

/** @} */

#ifdef __cplusplus
}
#endif
#endif /* _LIBCRYPTSETUP_H */
