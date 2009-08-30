#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>

#include "libcryptsetup.h"
#include "luks.h"
#include "internal.h"

struct crypt_device {
	/* callbacks definitions */
	void (*log)(int class, const char *msg, void *usrptr);
	void *log_usrptr;
};

/* Log helper */
static void (*_default_log)(int class, char *msg) = NULL;
static int _debug_level = 0;

void crypt_set_debug_level(int level)
{
	_debug_level = level;
}

void set_default_log(void (*log)(int class, char *msg))
{
	_default_log = log;
}

void logger(struct crypt_device *cd, int class, const char *file,
	    int line, const char *format, ...)
{
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0) {
		if (class >= 0) {
			if (cd && cd->log)
				cd->log(class, target, cd->log_usrptr);
			else if (_default_log)
				_default_log(class, target);
#ifdef CRYPT_DEBUG
		} else if (_debug_level)
			printf("# %s:%d %s\n", file ?: "?", line, target);
#else
		} else if (_debug_level)
			printf("# %s\n", target);
#endif
	}

	va_end(argp);
	free(target);
}

static void hexprintICB(struct crypt_device *cd, char *d, int n)
{
	int i;
	for(i = 0; i < n; i++)
		log_std(cd, "%02hhx ", (char)d[i]);
}

/*
 * Password processing behaviour matrix of process_key
 * 
 * from binary file: check if there is sufficently large key material
 * interactive & from fd: hash if requested, otherwise crop or pad with '0'
 */
static char *process_key(struct crypt_device *cd,
			 struct crypt_options *options,
			 const char *pass, size_t passLen)
{
	char *key = safe_alloc(options->key_size);
	memset(key, 0, options->key_size);

	/* key is coming from binary file */
	if (options->key_file && strcmp(options->key_file, "-")) {
		if(passLen < options->key_size) {
			log_err(cd, _("Cannot not read %d bytes from key file %s.\n"),
				options->key_size, options->key_file);
			safe_free(key);
			return NULL;
		}
		memcpy(key,pass,options->key_size);
		return key;
	}

	/* key is coming from tty, fd or binary stdin */
	if (options->hash) {
		if (hash(NULL, options->hash,
			 key, options->key_size,
			 pass, passLen) < 0)
		{
			log_err(cd, _("Key processing error.\n"));
			safe_free(key);
			return NULL;
		}
	} else if (passLen > options->key_size) {
		memcpy(key, pass, options->key_size);
	} else {
		memcpy(key, pass, passLen);
	}

	return key;
}

int parse_into_name_and_mode(const char *nameAndMode, char *name, char *mode)
{
/* Token content stringification, see info cpp/stringification */
#define str(s) #s
#define xstr(s) str(s)
#define scanpattern1 "%" xstr(LUKS_CIPHERNAME_L) "[^-]-%" xstr(LUKS_CIPHERMODE_L)  "s"
#define scanpattern2 "%" xstr(LUKS_CIPHERNAME_L) "[^-]"

	int r;

	if(sscanf(nameAndMode,scanpattern1, name, mode) != 2) {
		if((r = sscanf(nameAndMode,scanpattern2,name)) == 1)
			strncpy(mode,"cbc-plain",10);
		else
			return -EINVAL;
	}

	return 0;

#undef scanpattern1
#undef scanpattern2
#undef str
#undef xstr
}

static int keyslot_is_valid(struct crypt_device *cd, int keySlotIndex)
{
	if(keySlotIndex >= LUKS_NUMKEYS || keySlotIndex < 0) {
			log_err(cd, _("Key slot %d is invalid, please select between 0 and %d.\n"),
				keySlotIndex, LUKS_NUMKEYS - 1);
		return 0;
	}

	return 1;
}

/* Select free keyslot or verifies that the one specified is empty */
static int keyslot_from_option(struct crypt_device *cd, int keySlotOption, struct luks_phdr *hdr) {
        if(keySlotOption >= 0) {
                if(!keyslot_is_valid(cd, keySlotOption))
                        return -EINVAL;
                else if(hdr->keyblock[keySlotOption].active != LUKS_KEY_DISABLED) {
			log_err(cd, _("Key slot %d is full, please select another one.\n"),
				keySlotOption);
                        return -EINVAL;
                } else {
                        return keySlotOption;
                }
        } else {
                int i;
                /* Find empty key slot */
                for(i=0; i<LUKS_NUMKEYS; i++) {
                        if(hdr->keyblock[i].active == LUKS_KEY_DISABLED) break;
                }
                if(i==LUKS_NUMKEYS) {
			log_err(cd, _("All key slots full.\n"));
                        return -EINVAL;
                }
                return i;
        }
}

static int create_device_helper(int reload, struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct device_infos infos;
	char *key = NULL;
	unsigned int keyLen;
	char *processed_key = NULL;
	int r;

	r = dm_status_device(options->name);
	if (reload) {
		if (r < 0)
			return r;
	} else {
		if (r >= 0) {
			log_err(cd, _("Device %s already exists.\n"), options->name);
			return -EEXIST;
		}
		if (r != -ENODEV)
			return r;
	}

	if (options->key_size < 0 || options->key_size > 1024) {
		log_err(cd, _("Invalid key size %d.\n"), options->key_size);
		return -EINVAL;
	}

	if (get_device_infos(options->device, &infos, cd) < 0)
		return -ENOTBLK;

	if (!options->size) {
		options->size = infos.size;
		if (!options->size) {
			log_err(cd, "Not a block device");
			return -ENOTBLK;
		}
		if (options->size <= options->offset) {
			log_err(cd, "Invalid offset");
			return -EINVAL;
		}
		options->size -= options->offset;
	}

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	get_key("Enter passphrase: ", &key, &keyLen, options->key_size,
		options->key_file, options->timeout, options->flags, NULL);
	if (!key) {
		log_err(cd, "Key reading error");
		return -ENOENT;
	}

	processed_key = process_key(cd, options, key, keyLen);
	safe_free(key);

	if (!processed_key)
		return -ENOENT;

	r = dm_create_device(options->name, options->device, options->cipher,
			     NULL, options->size, options->skip, options->offset,
			     options->key_size, processed_key,
			     options->flags & CRYPT_FLAG_READONLY, reload);

	safe_free(processed_key);

	return r;
}

static int luks_remove_helper(struct crypt_device *cd,
			      struct crypt_options *options, int supply_it)
{
	struct luks_masterkey *mk;
	struct luks_phdr hdr;
	char *password=NULL;
	unsigned int passwordLen;
	const char *device = options->device;
	int keyIndex;
	int openedIndex;
	int r, last_slot;

	r = LUKS_read_phdr(options->device, &hdr, 1, cd);
	if(r < 0)
		return r;

	if(supply_it) {
		get_key("Enter LUKS passphrase to be deleted: ",&password,&passwordLen, 0, options->new_key_file,
			options->timeout, options->flags, cd);
		if(!password) {
			r = -EINVAL; goto out;
		}

		keyIndex = LUKS_open_key_with_hdr(device, CRYPT_ANY_SLOT, password, passwordLen, &hdr, &mk, cd);
		if(keyIndex < 0) {
			log_err(cd, "No remaining key available with this passphrase.\n");
			r = -EPERM; goto out;
		} else
			log_std(cd ,"key slot %d selected for deletion.\n", keyIndex);

		safe_free(password);
		password = NULL;
	} else {
		keyIndex = options->key_slot;
		if (!keyslot_is_valid(cd, keyIndex)) {
			r = -EINVAL; goto out;
		}
	}

	if (LUKS_keyslot_info(&hdr, keyIndex) == SLOT_INACTIVE) {
		log_err(cd, _("Key %d not active. Can't wipe.\n"), keyIndex);
		r = -EINVAL;
		goto out;
	}

	last_slot = (LUKS_keyslot_info(&hdr, keyIndex) == SLOT_ACTIVE_LAST);
	if(last_slot && !(options->icb->yesDialog(_("This is the last keyslot. Device will become unusable after purging this key.")))) {
		r = -EINVAL; goto out;
	}

	if(options->flags & CRYPT_FLAG_VERIFY_ON_DELKEY) {
		options->flags &= ~CRYPT_FLAG_VERIFY_ON_DELKEY;
		get_key("Enter any remaining LUKS passphrase: ",&password,&passwordLen, 0, options->key_file,
			options->timeout, options->flags, cd);
		if(!password) {
			r = -EINVAL; goto out;
		}

                r = LUKS_read_phdr(device, &hdr, 1, cd);
                if(r < 0) {
                        options->icb->log(CRYPT_LOG_ERROR,"Failed to access device.\n");
                        r = -EIO; goto out;
                }

		if(!last_slot)
			hdr.keyblock[keyIndex].active = LUKS_KEY_DISABLED;

		openedIndex = LUKS_open_key_with_hdr(device, CRYPT_ANY_SLOT, password, passwordLen, &hdr, &mk, cd);
                /* Clean up */
                if (openedIndex >= 0) {
                        LUKS_dealloc_masterkey(mk);
                        mk = NULL;
                }
		if(openedIndex < 0) {
                            log_err(cd, "No remaining key available with this passphrase.\n");
			    r = -EPERM; goto out;
		} else
                        log_std(cd, "key slot %d verified.\n", openedIndex);
	}
	r = LUKS_del_key(device, keyIndex, cd);
	if(r < 0) goto out;

	r = 0;
out:
	safe_free(password);
	return r;
}

/* OPTIONS: name, cipher, device, hash, key_file, key_size, key_slot,
 *          offset, size, skip, timeout, tries, passphrase_fd (ignored),
 *          flags, icb */
int crypt_create_device(struct crypt_options *options)
{
	return create_device_helper(0, options);
}

/* OPTIONS: same as create above */
int crypt_update_device(struct crypt_options *options)
{
	return create_device_helper(1, options);
}

/* OPTIONS: name, size, icb */
int crypt_resize_device(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	char *device, *cipher, *key = NULL;
	uint64_t size, skip, offset;
	int key_size, read_only, r;
	struct device_infos infos;

	r = dm_query_device(options->name, &device, &size, &skip, &offset,
			    &cipher, &key_size, &key, &read_only);
	if (r < 0)
		return r;

	if (get_device_infos(device, &infos, cd) < 0)
		return -EINVAL;

	if (!options->size) {
		options->size = infos.size;
		if (!options->size) {
			log_err(cd, "Not a block device");
			return -ENOTBLK;
		}
		if (options->size <= offset) {
			log_err(cd, "Invalid offset");
			return -EINVAL;
		}
		options->size -= offset;
	}
	size = options->size;

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	r = dm_create_device(options->name, device, cipher, NULL, size, skip, offset,
			     key_size, key, read_only, 1);

	safe_free(key);
	free(cipher);
	free(device);

	return r;
}

/* OPTIONS: name, icb */
int crypt_query_device(struct crypt_options *options)
{
	int read_only, r;

	r = dm_status_device(options->name);
	if (r == -ENODEV)
		return 0;

	r = dm_query_device(options->name, (char **)&options->device, &options->size,
			    &options->skip, &options->offset, (char **)&options->cipher,
			    &options->key_size, NULL, &read_only);

	if (r < 0)
		return r;

	if (read_only)
		options->flags |= CRYPT_FLAG_READONLY;

	options->flags |= CRYPT_FLAG_FREE_DEVICE;
	options->flags |= CRYPT_FLAG_FREE_CIPHER;

	return 1;
}

/* OPTIONS: name, icb */
int crypt_remove_device(struct crypt_options *options)
{
	int r;

	r = dm_status_device(options->name);
	if (r < 0)
		return r;
	if (r > 0) {
		log_err(NULL, "Device busy");
		return -EBUSY;
	}

	return dm_remove_device(options->name, 0, 0);
}

/* OPTIONS: device, cipher, hash, align_payload, key_size (master key), key_slot
 *          new_key_file, iteration_time, timeout, flags, icb */
int crypt_luksFormat(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_phdr header;
	struct luks_masterkey *mk=NULL;
	char *password=NULL; 
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	unsigned int passwordLen;
	uint64_t PBKDF2perSecond = 0;
        int r, keyIndex;

	if (!device_ready(cd, options->device, O_RDWR | O_EXCL))
		return -ENOTBLK;

	mk = LUKS_generate_masterkey(options->key_size);
	if(NULL == mk) return -ENOMEM; // FIXME This may be misleading, since we don't know what went wrong

#ifdef LUKS_DEBUG
#define printoffset(entry) \
	logger(options, CRYPT_LOG_ERROR, \
	        "offset of " #entry " = %d\n", (char *)(&header.entry)-(char *)(&header))

	log_err("sizeof phdr %d, sizeof key slot %d\n",
		sizeof(struct luks_phdr),
		sizeof(header.keyblock[0]));

	printoffset(magic);
	printoffset(version);
	printoffset(cipherName);
	printoffset(cipherMode);
	printoffset(hashSpec);
	printoffset(payloadOffset);
	printoffset(keyBytes);
	printoffset(mkDigest);
	printoffset(mkDigestSalt);
	printoffset(mkDigestIterations);
	printoffset(uuid);
#endif

	r = parse_into_name_and_mode(options->cipher, cipherName, cipherMode);
	if(r < 0) {
		log_err(cd, _("No known cipher specification pattern detected.\n"));
		return r;
	}

	r = LUKS_generate_phdr(&header, mk, cipherName, cipherMode, options->hash, NULL, LUKS_STRIPES, options->align_payload, NULL);
	if(r < 0) return r;

	keyIndex = keyslot_from_option(NULL, options->key_slot, &header);
	if(keyIndex == -EINVAL) {
		r = -EINVAL; goto out;
	}

	get_key("Enter LUKS passphrase: ",&password,&passwordLen, 0, options->new_key_file,
		options->timeout, options->flags, NULL);
	if(!password) {
		r = -EINVAL; goto out;
	}

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = wipe_device_header(options->device, 8);
	if(r < 0) goto out;

	/* Set key, also writes phdr */
	r = LUKS_set_key(options->device, keyIndex, password, passwordLen, &header, mk,
			 options->iteration_time, &PBKDF2perSecond, NULL);
	if(r < 0) goto out; 

	r = 0;
out:
	LUKS_dealloc_masterkey(mk);
	safe_free(password);
	return r;
}

/* OPTIONS: name, device, key_size, key_file, timeout, tries, flags, icb */
int crypt_luksOpen(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_masterkey *mk=NULL;
	struct luks_phdr hdr;
	char *prompt = NULL;
	char *password;
	unsigned int passwordLen;
	struct device_infos infos;
	char *dmCipherSpec = NULL;
	int r, tries = options->tries;
	int excl = (options->flags & CRYPT_FLAG_NON_EXCLUSIVE_ACCESS) ? 0 : O_EXCL ;

	r = dm_status_device(options->name);
	if (r >= 0) {
		log_err(cd, "Device %s already exists.", options->name);
		return -EEXIST;
	}

	if (!device_ready(cd, options->device, O_RDONLY | excl))
		return -ENOTBLK;

	if (get_device_infos(options->device, &infos, cd) < 0) {
		log_err(cd, "Can't get device information.\n");
		return -ENOTBLK;
	}

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	if(asprintf(&prompt, "Enter LUKS passphrase for %s: ", options->device) < 0)
		return -ENOMEM;

start:
	mk=NULL;

	if(options->passphrase) {
		passwordLen = strlen(options->passphrase);
		password = safe_alloc(passwordLen + 1);
		strncpy(password, options->passphrase, passwordLen + 1);
		tries = 0;
	} else {
		get_key(prompt, &password, &passwordLen, options->key_size, options->key_file,
			options->timeout, options->flags, cd);
		if (password)
			tries--;
		else
			tries = 0;
	}

	if(!password) {
		r = -EINVAL; goto out;
	}

	r = LUKS_read_phdr(options->device, &hdr, 1, cd);
	if(r < 0)
		return r;

	r = LUKS_open_key_with_hdr(options->device, CRYPT_ANY_SLOT, password, passwordLen, &hdr, &mk, cd);
	if (r == -EPERM)
		log_err(cd, "No key available with this passphrase.\n");
	if (r < 0)
		goto out1;

	log_err(NULL, "key slot %d unlocked.\n", r);


	options->offset = hdr.payloadOffset;
 	if (asprintf(&dmCipherSpec, "%s-%s", hdr.cipherName, hdr.cipherMode) < 0) {
		r = -ENOMEM;
		goto out2;
	}
	options->cipher = dmCipherSpec;
	options->key_size = mk->keyLength;
	options->skip = 0;

	options->size = infos.size;
	if (!options->size) {
		log_err(cd, "Not a block device.\n");
		r = -ENOTBLK; goto out2;
	}
	if (options->size <= options->offset) {
		log_err(cd, "Invalid offset");
		r = -EINVAL; goto out2;
	}
	options->size -= options->offset;
	/* FIXME: code allows multiple crypt mapping, cannot use uuid then.
	 * anyway, it is dangerous and can corrupt data. Remove it in next version! */
	r = dm_create_device(options->name, options->device, options->cipher,
			     excl ? hdr.uuid : NULL, options->size,
			     0, options->offset, mk->keyLength, mk->key,
			     options->flags & CRYPT_FLAG_READONLY, 0);

 out2:
	free(dmCipherSpec);
	dmCipherSpec = NULL;
 out1:
	safe_free(password);
 out:
	LUKS_dealloc_masterkey(mk);
	if (r == -EPERM && tries > 0)
		goto start;

	free(prompt);

	return r;
}

/* OPTIONS: device, keys_slot, key_file, timeout, flags, icb */
int crypt_luksKillSlot(struct crypt_options *options)
{
	return luks_remove_helper(NULL, options, 0);
}

/* OPTIONS: device, new_key_file, key_file, timeout, flags, icb */
int crypt_luksRemoveKey(struct crypt_options *options)
{
	return luks_remove_helper(NULL, options, 1);
}

/* OPTIONS: device, new_key_file, key_file, key_slot, flags,
            iteration_time, timeout, icb */
int crypt_luksAddKey(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_masterkey *mk=NULL;
	struct luks_phdr hdr;
	char *password=NULL; unsigned int passwordLen;
	unsigned int keyIndex;
	uint64_t PBKDF2perSecond = 0;
	const char *device = options->device;
	int r;

	if (!device_ready(cd, options->device, O_RDWR))
		return -ENOTBLK;

	r = LUKS_read_phdr(device, &hdr, 1, cd);
	if(r < 0) return r;


        keyIndex = keyslot_from_option(cd, options->key_slot, &hdr);
        if(keyIndex == -EINVAL) {
                r = -EINVAL; goto out;
        }

	get_key("Enter any LUKS passphrase: ",
                &password,
                &passwordLen, 
                0,
                options->key_file, 
                options->timeout, 
                options->flags & ~(CRYPT_FLAG_VERIFY | CRYPT_FLAG_VERIFY_IF_POSSIBLE), cd);

	if(!password) {
		r = -EINVAL; goto out;
	}
	r = LUKS_open_key_with_hdr(device, CRYPT_ANY_SLOT, password, passwordLen, &hdr, &mk, cd);
	if(r < 0) {
	        options->icb->log(CRYPT_LOG_ERROR,"No key available with this passphrase.\n");
		r = -EPERM; goto out;
	}
	safe_free(password);

	get_key("Enter new passphrase for key slot: ",
                &password,
                &passwordLen,
                0,
                options->new_key_file,
                options->timeout, 
                options->flags, cd);
	if(!password) {
		r = -EINVAL; goto out;
	}

	r = LUKS_set_key(device, keyIndex, password, passwordLen, &hdr, mk, options->iteration_time, &PBKDF2perSecond, cd);
	if(r < 0) goto out;

	r = 0;
out:
	safe_free(password);
	LUKS_dealloc_masterkey(mk);
	return r;
}

/* OPTIONS: device, icb */
int crypt_luksUUID(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_phdr hdr;
	int r;

	r = LUKS_read_phdr(options->device, &hdr, 1, cd);
	if(r < 0) return r;

	options->icb->log(CRYPT_LOG_NORMAL,hdr.uuid);
	options->icb->log(CRYPT_LOG_NORMAL,"\n");
	return 0;
}

/* OPTIONS: device, icb */
int crypt_isLuks(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_phdr hdr;
	return LUKS_read_phdr(options->device, &hdr, 0, cd);
}

/* OPTIONS: device, icb */
int crypt_luksDump(struct crypt_options *options)
{
	struct crypt_device *cd = NULL;
	struct luks_phdr hdr;
	int r,i;

	r = LUKS_read_phdr(options->device, &hdr, 1, cd);
	if(r < 0) return r;

	log_std(cd, "LUKS header information for %s\n\n", options->device);
	log_std(cd, "Version:       \t%d\n", hdr.version);
	log_std(cd, "Cipher name:   \t%s\n", hdr.cipherName);
	log_std(cd, "Cipher mode:   \t%s\n", hdr.cipherMode);
	log_std(cd, "Hash spec:     \t%s\n", hdr.hashSpec);
	log_std(cd, "Payload offset:\t%d\n", hdr.payloadOffset);
	log_std(cd, "MK bits:       \t%d\n", hdr.keyBytes * 8);
	log_std(cd, "MK digest:     \t");
	hexprintICB(cd, hdr.mkDigest, LUKS_DIGESTSIZE);
	log_std(cd, "\n");
	log_std(cd, "MK salt:       \t");
	hexprintICB(cd, hdr.mkDigestSalt, LUKS_SALTSIZE/2);
	log_std(cd, "\n               \t");
	hexprintICB(cd, hdr.mkDigestSalt+LUKS_SALTSIZE/2, LUKS_SALTSIZE/2);
	log_std(cd, "\n");
	log_std(cd, "MK iterations: \t%d\n", hdr.mkDigestIterations);
	log_std(cd, "UUID:          \t%s\n\n", hdr.uuid);
	for(i = 0; i < LUKS_NUMKEYS; i++) {
		if(hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			log_std(cd, "Key Slot %d: ENABLED\n",i);
			log_std(cd, "\tIterations:         \t%d\n",
				hdr.keyblock[i].passwordIterations);
			log_std(cd, "\tSalt:               \t");
			hexprintICB(cd, hdr.keyblock[i].passwordSalt,
				    LUKS_SALTSIZE/2);
			log_std(cd, "\n\t                      \t");
			hexprintICB(cd, hdr.keyblock[i].passwordSalt +
				    LUKS_SALTSIZE/2, LUKS_SALTSIZE/2);
			log_std(cd, "\n");

			log_std(cd, "\tKey material offset:\t%d\n",
				hdr.keyblock[i].keyMaterialOffset);
			log_std(cd, "\tAF stripes:            \t%d\n",
				hdr.keyblock[i].stripes);
		}
		else 
			log_std(cd, "Key Slot %d: DISABLED\n", i);
	}
	return 0;
}

void crypt_get_error(char *buf, size_t size)
{
	const char *error = get_error();

	if (!buf || size < 1)
		set_error(NULL);
	else if (error) {
		strncpy(buf, error, size - 1);
		buf[size - 1] = '\0';
		set_error(NULL);
	} else
		buf[0] = '\0';
}

void crypt_put_options(struct crypt_options *options)
{
	if (options->flags & CRYPT_FLAG_FREE_DEVICE) {
		free((char *)options->device);
		options->device = NULL;
		options->flags &= ~CRYPT_FLAG_FREE_DEVICE;
	}
	if (options->flags & CRYPT_FLAG_FREE_CIPHER) {
		free((char *)options->cipher);
		options->cipher = NULL;
		options->flags &= ~CRYPT_FLAG_FREE_CIPHER;
	}
}

const char *crypt_get_dir(void)
{
	return dm_get_dir();
}
