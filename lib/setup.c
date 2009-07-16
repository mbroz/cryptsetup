#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include "libcryptsetup.h"
#include "internal.h"
#include "blockdev.h"
#include "luks.h"

struct device_infos {
	uint64_t	size;
	int		readonly;
};

static int memory_unsafe = 0;
static char *default_backend = NULL;

#define at_least_one(a) ({ __typeof__(a) __at_least_one=(a); (__at_least_one)?__at_least_one:1; })

static void logger(struct crypt_options *options, int class, char *format, ...) {
	va_list argp;
	char *target = NULL;

	va_start(argp, format);

	if (vasprintf(&target, format, argp) > 0)
		options->icb->log(class, target);

	va_end(argp);
	free(target);
}

static void hexprintICB(struct crypt_options *options, int class, char *d, int n)
{
	int i;
	for(i = 0; i < n; i++)
		logger(options, class, "%02hhx ", (char)d[i]);
}

static int setup_enter(struct setup_backend *backend, void (*log)(int, char *))
{
	int r;

	/*
	 * from here we could have sensible data in memory
	 * so protect it from being swapped out
	 */
	r = mlockall(MCL_CURRENT | MCL_FUTURE);
	if (r < 0) {
		perror("mlockall failed");
		log(CRYPT_LOG_ERROR, "WARNING!!! Possibly insecure memory. Are you root?\n");
		memory_unsafe = 1;
	}

	set_error(NULL);

	if (backend) {
		r = backend->init();
		if (r < 0)
			return r;
		if (r > 0)
			memory_unsafe = 1;
	}

	return 0;
}

static int setup_leave(struct setup_backend *backend)
{
	if (backend)
		backend->exit();

	/* dangerous, we can't wipe all the memory */
	if (!memory_unsafe)
		munlockall();

	return 0;
}

/*
 * Password processing behaviour matrix of process_key
 * 
 * from binary file: check if there is sufficently large key material
 * interactive & from fd: hash if requested, otherwise crop or pad with '0'
 */

static char *process_key(struct crypt_options *options, char *pass, int passLen) {
	char *key = safe_alloc(options->key_size);
	memset(key, 0, options->key_size);

	/* key is coming from binary file */
	if (options->key_file && strcmp(options->key_file, "-")) {
		if(passLen < options->key_size) {
			set_error("Could not read %d bytes from key file",
			          options->key_size);
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

static int get_device_infos(const char *device, struct device_infos *infos)
{
	char buf[128];
	uint64_t size;
	unsigned long size_small;
	int readonly = 0;
	int ret = -1;
	int fd;

	/* Try to open read-write to check whether it is a read-only device */
	fd = open(device, O_RDWR);
	if (fd < 0) {
		if (errno == EROFS) {
			readonly = 1;
			fd = open(device, O_RDONLY);
		}
	} else {
		close(fd);
		fd = open(device, O_RDONLY);
	}
	if (fd < 0) {
		set_error("Error opening device: %s",
		          strerror_r(errno, buf, 128));
		return -1;
	}

#ifdef BLKROGET
	/* If the device can be opened read-write, i.e. readonly is still 0, then
	 * check whether BKROGET says that it is read-only. E.g. read-only loop
	 * devices may be openend read-write but are read-only according to BLKROGET
	 */
	if (readonly == 0) {
		if (ioctl(fd, BLKROGET, &readonly) < 0) {
			set_error("BLKROGET failed on device: %s",
			          strerror_r(errno, buf, 128));
			return -1;
		}
	}
#else
#error BLKROGET not available
#endif

#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, &size) >= 0) {
		size >>= SECTOR_SHIFT;
		ret = 0;
		goto out;
	}
#endif

#ifdef BLKGETSIZE
	if (ioctl(fd, BLKGETSIZE, &size_small) >= 0) {
		size = (uint64_t)size_small;
		ret = 0;
		goto out;
	}
#else
#	error Need at least the BLKGETSIZE ioctl!
#endif

	set_error("BLKGETSIZE ioctl failed on device: %s",
	          strerror_r(errno, buf, 128));

out:
	if (ret == 0) {
		infos->size = size;
		infos->readonly = readonly;
	}
	close(fd);
	return ret;
}

static int wipe_device_header(const char *device, int sectors)
{
	char *buffer;
	int size = sectors * SECTOR_SIZE;
	int r = -1;
	int devfd;

	devfd = open(device, O_RDWR | O_DIRECT | O_SYNC);
	if(devfd == -1) {
		set_error("Can't wipe header on device %s", device);
		return -EINVAL;
	}

	buffer = malloc(size);
	if (!buffer) {
		close(devfd);
		return -ENOMEM;
	}
	memset(buffer, 0, size);

	r = write_blockwise(devfd, buffer, size) < size ? -EIO : 0;

	free(buffer);
	close(devfd);

	return r;
}

static int parse_into_name_and_mode(const char *nameAndMode, char *name,
				    char *mode)
{
/* Token content stringification, see info cpp/stringification */
#define str(s) #s
#define xstr(s) str(s)
#define scanpattern1 "%" xstr(LUKS_CIPHERNAME_L) "[^-]-%" xstr(LUKS_CIPHERMODE_L)  "s"
#define scanpattern2 "%" xstr(LUKS_CIPHERNAME_L) "[^-]"

	int r;

	if(sscanf(nameAndMode,scanpattern1, name, mode) != 2) {
		if((r = sscanf(nameAndMode,scanpattern2,name)) == 1) {
			strncpy(mode,"cbc-plain",10);
		} 
		else {
			set_error("no known cipher-spec pattern detected");
			return -EINVAL;
		}
	}

	return 0;

#undef sp1
#undef sp2
#undef str
#undef xstr
}

/* Select free keyslot or verifies that the one specified is empty */
static int keyslot_from_option(int keySlotOption, struct luks_phdr *hdr, struct crypt_options *options) {
        if(keySlotOption >= 0) {
                if(keySlotOption >= LUKS_NUMKEYS) {
                        logger(options,CRYPT_LOG_ERROR,"slot %d too high, please pick between 0 and %d", keySlotOption, LUKS_NUMKEYS);
                        return -EINVAL;
                } else if(hdr->keyblock[keySlotOption].active != LUKS_KEY_DISABLED) {
                        logger(options,CRYPT_LOG_ERROR,"slot %d full, please pick another one", keySlotOption);
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
                        logger(options,CRYPT_LOG_ERROR,"All slots full");
                        return -EINVAL;
                }
                return i;
        }
}

static int __crypt_create_device(int reload, struct setup_backend *backend,
                                 struct crypt_options *options)
{
	struct crypt_options tmp = {
		.name = options->name,
	};
	struct device_infos infos;
	char *key = NULL;
	unsigned int keyLen;
	char *processed_key = NULL;
	int r;

	r = backend->status(0, &tmp, NULL);
	if (reload) {
		if (r < 0)
			return r;
	} else {
		if (r >= 0) {
			set_error("Device %s already exists.", options->name);
			return -EEXIST;
		}
		if (r != -ENODEV)
			return r;
	}

	if (options->key_size < 0 || options->key_size > 1024) {
		set_error("Invalid key size");
		return -EINVAL;
	}

	if (get_device_infos(options->device, &infos) < 0)
		return -ENOTBLK;

	if (!options->size) {
		options->size = infos.size;
		if (!options->size) {
			set_error("Not a block device");
			return -ENOTBLK;
		}
		if (options->size <= options->offset) {
			set_error("Invalid offset");
			return -EINVAL;
		}
		options->size -= options->offset;
	}

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	get_key("Enter passphrase: ", &key, &keyLen, options->key_size, options->key_file, options->passphrase_fd, options->timeout, options->flags);
	if (!key) {
		set_error("Key reading error");
		return -ENOENT;
	}

	processed_key = process_key(options,key,keyLen);
	safe_free(key);

	if (!processed_key) {
		const char *error=get_error();
		if(error) {
			char *c_error_handling_sucks = NULL;
			if (asprintf(&c_error_handling_sucks,"Key processing error: %s",error) > 0)
				set_error(c_error_handling_sucks);
			free(c_error_handling_sucks);
		} else
			set_error("Key processing error");
		return -ENOENT;
	}

	r = backend->create(reload, options, processed_key, NULL);

	safe_free(processed_key);

	return r;
}

static int __crypt_query_device(int details, struct setup_backend *backend,
                                struct crypt_options *options)
{
	int r = backend->status(details, options, NULL);
	if (r == -ENODEV)
		return 0;
	else if (r >= 0)
		return 1;
	else
		return r;
}

static int __crypt_resize_device(int details, struct setup_backend *backend,
                                struct crypt_options *options)
{
	struct crypt_options tmp = {
		.name = options->name,
	};
	struct device_infos infos;
	char *key = NULL;
	int r;

	r = backend->status(1, &tmp, &key);
	if (r < 0)
		return r;

	if (get_device_infos(tmp.device, &infos) < 0)
		return -EINVAL;

	if (!options->size) {
		options->size = infos.size;
		if (!options->size) {
			set_error("Not a block device");
			return -ENOTBLK;
		}
		if (options->size <= tmp.offset) {
			set_error("Invalid offset");
			return -EINVAL;
		}
		options->size -= tmp.offset;
	}
	tmp.size = options->size;

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	r = backend->create(1, &tmp, key, NULL);

	safe_free(key);

	return r;
}

static int __crypt_remove_device(int arg, struct setup_backend *backend,
                                 struct crypt_options *options)
{
	int r;

	r = backend->status(0, options, NULL);
	if (r < 0)
		return r;
	if (r > 0) {
		set_error("Device busy");
		return -EBUSY;
	}

	return backend->remove(0, options);
}

static int __crypt_luks_format(int arg, struct setup_backend *backend, struct crypt_options *options)
{
	int r;

	struct luks_phdr header;
	struct luks_masterkey *mk=NULL;
	char *password=NULL; 
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	unsigned int passwordLen;
	int PBKDF2perSecond;
        int keyIndex;

	if (!LUKS_device_ready(options->device, O_RDWR | O_EXCL))
		return -ENOTBLK;

	mk = LUKS_generate_masterkey(options->key_size);
	if(NULL == mk) return -ENOMEM; // FIXME This may be misleading, since we don't know what went wrong

#ifdef LUKS_DEBUG
#define printoffset(entry) logger(options, CRYPT_LOG_ERROR, ("offset of " #entry " = %d\n", (char *)(&header.entry)-(char *)(&header))

	logger(options, CRYPT_LOG_ERROR, "sizeof phdr %d, key slot %d\n",sizeof(struct luks_phdr),sizeof(header.keyblock[0]));

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
	if(r < 0) return r;

	r = LUKS_generate_phdr(&header,mk,cipherName, cipherMode,LUKS_STRIPES, options->align_payload);
	if(r < 0) {
		set_error("Can't generate phdr");
		return r; 
	}

        keyIndex = keyslot_from_option(options->key_slot, &header, options);
        if(keyIndex == -EINVAL) {
                r = -EINVAL; goto out;
        }

	PBKDF2perSecond = LUKS_benchmarkt_iterations();
	header.keyblock[keyIndex].passwordIterations = at_least_one(PBKDF2perSecond * ((float)options->iteration_time / 1000.0));
#ifdef LUKS_DEBUG
	logger(options->icb->log,CRYPT_LOG_ERROR, "pitr %d\n", header.keyblock[0].passwordIterations);
#endif
	get_key("Enter LUKS passphrase: ",&password,&passwordLen, 0, options->new_key_file, options->passphrase_fd, options->timeout, options->flags);
	if(!password) {
		r = -EINVAL; goto out;
	}

	/* Wipe first 8 sectors - fs magic numbers etc. */
	r = wipe_device_header(options->device, 8);
	if(r < 0) goto out;

	/* Set key, also writes phdr */
	r = LUKS_set_key(options->device, keyIndex, password, passwordLen, &header, mk, backend);
	if(r < 0) goto out; 

	r = 0;
out:
	LUKS_dealloc_masterkey(mk);
	safe_free(password);
	return r;
}

static int __crypt_luks_open(int arg, struct setup_backend *backend, struct crypt_options *options)
{
	struct luks_masterkey *mk=NULL;
	struct luks_phdr hdr;
	char *prompt = NULL;
	char *password;
	unsigned int passwordLen;
	struct device_infos infos;
	struct crypt_options tmp = {
		.name = options->name,
	};
	char *dmCipherSpec = NULL;
	int r, tries = options->tries;
	int excl = (options->flags & CRYPT_FLAG_NON_EXCLUSIVE_ACCESS) ? 0 : O_EXCL ;

	r = backend->status(0, &tmp, NULL);
	if (r >= 0) {
		set_error("Device %s already exists.", options->name);
		return -EEXIST;
	}

	if (!LUKS_device_ready(options->device, O_RDONLY | excl))
		return -ENOTBLK;

	if (get_device_infos(options->device, &infos) < 0) {
		set_error("Can't get device information.\n");
		return -ENOTBLK;
	}

	if (infos.readonly)
		options->flags |= CRYPT_FLAG_READONLY;

	if(asprintf(&prompt, "Enter LUKS passphrase for %s: ", options->device) < 0)
		return -ENOMEM;

start:
	mk=NULL;

	if(get_key(prompt, &password, &passwordLen, 0, options->key_file, options->passphrase_fd, options->timeout, options->flags))
		tries--;
	else
		tries = 0;

	if(!password) {
		r = -EINVAL; goto out;
	}

        r = LUKS_open_any_key(options->device, password, passwordLen, &hdr, &mk, backend);
	if (r == -EPERM)
		set_error("No key available with this passphrase.\n");
	if (r < 0)
		goto out1;

	logger(options, CRYPT_LOG_NORMAL,"key slot %d unlocked.\n", r);


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
		set_error("Not a block device.\n");
		r = -ENOTBLK; goto out2;
	}
	if (options->size <= options->offset) {
		set_error("Invalid offset");
		r = -EINVAL; goto out2;
	}
	options->size -= options->offset;
	/* FIXME: code allows multiple crypt mapping, cannot use uuid then.
	 * anyway, it is dangerous and can corrupt data. Remove it in next version! */
	r = backend->create(0, options, mk->key, excl ? hdr.uuid : NULL);

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

static int __crypt_luks_add_key(int arg, struct setup_backend *backend, struct crypt_options *options)
{
	struct luks_masterkey *mk=NULL;
	struct luks_phdr hdr;
	char *password=NULL; unsigned int passwordLen;
        unsigned int keyIndex;
	const char *device = options->device;
	int r;

	if (!LUKS_device_ready(options->device, O_RDWR))
		return -ENOTBLK;

	r = LUKS_read_phdr(device, &hdr);
	if(r < 0) return r;


        keyIndex = keyslot_from_option(options->key_slot, &hdr, options);
        if(keyIndex == -EINVAL) {
                r = -EINVAL; goto out;
        }

	get_key("Enter any LUKS passphrase: ",
                &password,
                &passwordLen, 
                0,
                options->key_file, 
                options->passphrase_fd, 
                options->timeout, 
                options->flags & ~(CRYPT_FLAG_VERIFY | CRYPT_FLAG_VERIFY_IF_POSSIBLE));

	if(!password) {
		r = -EINVAL; goto out;
	}
	r = LUKS_open_any_key(device, password, passwordLen, &hdr, &mk, backend);
	if(r < 0) {
	        options->icb->log(CRYPT_LOG_ERROR,"No key available with this passphrase.\n");
		r = -EPERM; goto out;
	} else
	        logger(options, CRYPT_LOG_NORMAL,"key slot %d unlocked.\n", r);

	safe_free(password);

	get_key("Enter new passphrase for key slot: ",
                &password,
                &passwordLen,
                0,
                options->new_key_file,
                options->passphrase_fd,
                options->timeout, 
                options->flags);
	if(!password) {
		r = -EINVAL; goto out;
	}

	hdr.keyblock[keyIndex].passwordIterations = at_least_one(LUKS_benchmarkt_iterations() * ((float)options->iteration_time / 1000));

    	r = LUKS_set_key(device, keyIndex, password, passwordLen, &hdr, mk, backend);
	if(r < 0) goto out;

	r = 0;
out:
	safe_free(password);
	LUKS_dealloc_masterkey(mk);
	return r;
}

static int luks_remove_helper(int arg, struct setup_backend *backend, struct crypt_options *options, int supply_it)
{
	struct luks_masterkey *mk;
	struct luks_phdr hdr;
	char *password=NULL; 
	unsigned int passwordLen;
	const char *device = options->device;
	int keyIndex;
	int openedIndex;
	int r, last_slot;

	if (!LUKS_device_ready(options->device, O_RDWR))
	    return -ENOTBLK;

	if(supply_it) {
	    get_key("Enter LUKS passphrase to be deleted: ",&password,&passwordLen, 0, options->new_key_file, options->passphrase_fd, options->timeout, options->flags);
	    if(!password) {
		    r = -EINVAL; goto out;
	    }
	    keyIndex = LUKS_open_any_key(device, password, passwordLen, &hdr, &mk, backend);
	    if(keyIndex < 0) {
		    options->icb->log(CRYPT_LOG_ERROR,"No remaining key available with this passphrase.\n");
		    r = -EPERM; goto out;
	    } else
	        logger(options, CRYPT_LOG_NORMAL,"key slot %d selected for deletion.\n", keyIndex);
	    safe_free(password);
	} else {
	    keyIndex = options->key_slot;
	}

	last_slot = LUKS_is_last_keyslot(options->device, keyIndex);
	if(last_slot && !(options->icb->yesDialog(_("This is the last keyslot. Device will become unusable after purging this key.")))) {
		r = -EINVAL; goto out;
	}

	if(options->flags & CRYPT_FLAG_VERIFY_ON_DELKEY) {
		options->flags &= ~CRYPT_FLAG_VERIFY_ON_DELKEY;
		get_key("Enter any remaining LUKS passphrase: ",&password,&passwordLen, 0, options->key_file, options->passphrase_fd, options->timeout, options->flags);
		if(!password) {
			r = -EINVAL; goto out;
		}

                r = LUKS_read_phdr(device, &hdr);
                if(r < 0) { 
                        options->icb->log(CRYPT_LOG_ERROR,"Failed to access device.\n");
                        r = -EIO; goto out;
                }

		if(!last_slot)
			hdr.keyblock[keyIndex].active = LUKS_KEY_DISABLED;

		openedIndex = LUKS_open_any_key_with_hdr(device, password, passwordLen, &hdr, &mk, backend);
                /* Clean up */
                if (openedIndex >= 0) {
                        LUKS_dealloc_masterkey(mk);
                        mk = NULL;
                }
		if(openedIndex < 0) {
                            options->icb->log(CRYPT_LOG_ERROR,"No remaining key available with this passphrase.\n");
			    r = -EPERM; goto out;
		} else
                        logger(options, CRYPT_LOG_NORMAL,"key slot %d verified.\n", openedIndex);
	}
	r = LUKS_del_key(device, keyIndex);
	if(r < 0) goto out;

	r = 0;
out:
	safe_free(password);
	return r;
}

static int __crypt_luks_kill_slot(int arg, struct setup_backend *backend, struct crypt_options *options) {
	return luks_remove_helper(arg, backend, options, 0);
}

static int __crypt_luks_remove_key(int arg, struct setup_backend *backend, struct crypt_options *options) {
	return luks_remove_helper(arg, backend, options, 1);
}


static int crypt_job(int (*job)(int arg, struct setup_backend *backend,
                                struct crypt_options *options),
                     int arg, struct crypt_options *options)
{
	struct setup_backend *backend;
	int r;

	backend = get_setup_backend(default_backend);

	if (setup_enter(backend,options->icb->log) < 0) {
		r = -ENOSYS;
		goto out;
	}

	if (!backend) {
		set_error("No setup backend available");
		r = -ENOSYS;
		goto out;
	}

	r = job(arg, backend, options);
out:
	setup_leave(backend);
	if (backend)
		put_setup_backend(backend);

	if (r >= 0)
		set_error(NULL);

	return r;
}

int crypt_create_device(struct crypt_options *options)
{
	return crypt_job(__crypt_create_device, 0, options);
}

int crypt_update_device(struct crypt_options *options)
{
	return crypt_job(__crypt_create_device, 1, options);
}

int crypt_resize_device(struct crypt_options *options)
{
	return crypt_job(__crypt_resize_device, 0, options);
}

int crypt_query_device(struct crypt_options *options)
{
	return crypt_job(__crypt_query_device, 1, options);
}

int crypt_remove_device(struct crypt_options *options)
{
	return crypt_job(__crypt_remove_device, 0, options);

}

int crypt_luksFormat(struct crypt_options *options)
{
	return crypt_job(__crypt_luks_format, 0, options);
}

int crypt_luksOpen(struct crypt_options *options)
{
	return crypt_job(__crypt_luks_open, 0, options);
}

int crypt_luksKillSlot(struct crypt_options *options)
{
	return crypt_job(__crypt_luks_kill_slot, 0, options);
}

int crypt_luksRemoveKey(struct crypt_options *options)
{
	return crypt_job(__crypt_luks_remove_key, 0, options);
}

int crypt_luksAddKey(struct crypt_options *options)
{
	return crypt_job(__crypt_luks_add_key, 0, options);
}

int crypt_luksUUID(struct crypt_options *options)
{
	struct luks_phdr hdr;
	int r;

	r = LUKS_read_phdr(options->device,&hdr);
	if(r < 0) return r;

	options->icb->log(CRYPT_LOG_NORMAL,hdr.uuid);
	options->icb->log(CRYPT_LOG_NORMAL,"\n");
	return 0;
}

int crypt_isLuks(struct crypt_options *options)
{
	struct luks_phdr hdr;
	return LUKS_read_phdr(options->device,&hdr);
}

int crypt_luksDump(struct crypt_options *options)
{
	struct luks_phdr hdr;
	int r,i;

	r = LUKS_read_phdr(options->device,&hdr);
	if(r < 0) return r;

	logger(options, CRYPT_LOG_NORMAL, "LUKS header information for %s\n\n",options->device);
    	logger(options, CRYPT_LOG_NORMAL, "Version:       \t%d\n",hdr.version);
	logger(options, CRYPT_LOG_NORMAL, "Cipher name:   \t%s\n",hdr.cipherName);
	logger(options, CRYPT_LOG_NORMAL, "Cipher mode:   \t%s\n",hdr.cipherMode);
	logger(options, CRYPT_LOG_NORMAL, "Hash spec:     \t%s\n",hdr.hashSpec);
	logger(options, CRYPT_LOG_NORMAL, "Payload offset:\t%d\n",hdr.payloadOffset);
	logger(options, CRYPT_LOG_NORMAL, "MK bits:       \t%d\n",hdr.keyBytes*8);
	logger(options, CRYPT_LOG_NORMAL, "MK digest:     \t");
	hexprintICB(options, CRYPT_LOG_NORMAL, hdr.mkDigest,LUKS_DIGESTSIZE);
	logger(options, CRYPT_LOG_NORMAL, "\n");
	logger(options, CRYPT_LOG_NORMAL, "MK salt:       \t");
	hexprintICB(options, CRYPT_LOG_NORMAL, hdr.mkDigestSalt,LUKS_SALTSIZE/2);
	logger(options, CRYPT_LOG_NORMAL, "\n               \t");
	hexprintICB(options, CRYPT_LOG_NORMAL, hdr.mkDigestSalt+LUKS_SALTSIZE/2,LUKS_SALTSIZE/2);
	logger(options, CRYPT_LOG_NORMAL, "\n");
	logger(options, CRYPT_LOG_NORMAL, "MK iterations: \t%d\n",hdr.mkDigestIterations);
	logger(options, CRYPT_LOG_NORMAL, "UUID:          \t%s\n\n",hdr.uuid);
	for(i=0;i<LUKS_NUMKEYS;i++) {
		if(hdr.keyblock[i].active == LUKS_KEY_ENABLED) {
			logger(options, CRYPT_LOG_NORMAL, "Key Slot %d: ENABLED\n",i);
			logger(options, CRYPT_LOG_NORMAL, "\tIterations:         \t%d\n",hdr.keyblock[i].passwordIterations);
			logger(options, CRYPT_LOG_NORMAL, "\tSalt:               \t");
			hexprintICB(options, CRYPT_LOG_NORMAL, hdr.keyblock[i].passwordSalt,LUKS_SALTSIZE/2);
			logger(options, CRYPT_LOG_NORMAL, "\n\t                      \t");
			hexprintICB(options, CRYPT_LOG_NORMAL, hdr.keyblock[i].passwordSalt+LUKS_SALTSIZE/2,LUKS_SALTSIZE/2);
			logger(options, CRYPT_LOG_NORMAL, "\n");

			logger(options, CRYPT_LOG_NORMAL, "\tKey material offset:\t%d\n",hdr.keyblock[i].keyMaterialOffset);
			logger(options, CRYPT_LOG_NORMAL, "\tAF stripes:            \t%d\n",hdr.keyblock[i].stripes);
		}
		else 
			logger(options, CRYPT_LOG_NORMAL, "Key Slot %d: DISABLED\n",i);
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

void crypt_set_default_backend(const char *backend)
{
	if (default_backend)
		free(default_backend);
	if (backend) 
		default_backend = strdup(backend);
	else
		default_backend = NULL;
}

const char *crypt_get_dir(void)
{
	struct setup_backend *backend;
	const char *dir;

	backend = get_setup_backend(default_backend);
	if (!backend)
		return NULL;

	dir = backend->dir();

	put_setup_backend(backend);

	return dir;
}

// Local Variables:
// c-basic-offset: 8
// indent-tabs-mode: nil
// End:
