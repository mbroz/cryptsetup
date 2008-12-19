#ifndef INCLUDED_CRYPTSETUP_LUKS_LUKS_H
#define INCLUDED_CRYPTSETUP_LUKS_LUKS_H

/*
 * LUKS partition header
 */

#include <stddef.h>
#include <netinet/in.h>
#include "libcryptsetup.h"
#include "internal.h"

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20 // since SHA1
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8

// Numbers of iterations for the master key digest
#define LUKS_MKD_ITER 10

// LUKS_KT defines Key types

#define LUKS_KEY_DISABLED_OLD 0
#define LUKS_KEY_ENABLED_OLD 0xCAFE

#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED  0x00AC71F3

#define LUKS_STRIPES 4000

// partition header starts with magic

#define LUKS_MAGIC {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6

#define LUKS_PHDR_SIZE (sizeof(struct luks_phdr)/SECTOR_SIZE+1)

/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L 40

/* We don't have gettext support in LUKS */

#define _(Text) Text 

/* Any integer values are stored in network byte order on disk and must be
converted */

struct luks_phdr {
	char		magic[LUKS_MAGIC_L];
	uint16_t	version;
	char		cipherName[LUKS_CIPHERNAME_L];
	char		cipherMode[LUKS_CIPHERMODE_L];
	char            hashSpec[LUKS_HASHSPEC_L];
	uint32_t	payloadOffset;
	uint32_t	keyBytes;
	char		mkDigest[LUKS_DIGESTSIZE];
	char		mkDigestSalt[LUKS_SALTSIZE];
	uint32_t	mkDigestIterations;
	char            uuid[UUID_STRING_L];

	struct {
		uint32_t active;
	
		/* parameters used for password processing */
		uint32_t passwordIterations;
		char     passwordSalt[LUKS_SALTSIZE];
		
		/* parameters used for AF store/load */		
		uint32_t keyMaterialOffset;
		uint32_t stripes;		
	} keyblock[LUKS_NUMKEYS];
};

struct luks_masterkey {
	size_t keyLength;
	char key[];
};

struct luks_masterkey *LUKS_alloc_masterkey(int keylength);

void LUKS_dealloc_masterkey(struct luks_masterkey *mk);

struct luks_masterkey *LUKS_generate_masterkey(int keylength);

int LUKS_generate_phdr(struct luks_phdr *header,
		       const struct luks_masterkey *mk, const char *cipherName,
		       const char *cipherMode, unsigned int stripes,
		       unsigned int alignPayload);

int LUKS_read_phdr(const char *device, struct luks_phdr *hdr);

int LUKS_write_phdr(const char *device, struct luks_phdr *hdr);

int LUKS_set_key(const char *device, 
					unsigned int keyIndex, 
					const char *password, 
					size_t passwordLen, 
					struct luks_phdr *hdr, 
					struct luks_masterkey *mk,
					struct setup_backend *backend);

int LUKS_open_key(const char *device, 
					unsigned int keyIndex, 
					const char *password, 
					size_t passwordLen, 
					struct luks_phdr *hdr, 
					struct luks_masterkey *mk,
					struct setup_backend *backend);

int LUKS_open_any_key(const char *device, 
					const char *password, 
					size_t passwordLen, 
					struct luks_phdr *hdr, 
					struct luks_masterkey **mk,
					struct setup_backend *backend);

int LUKS_open_any_key_with_hdr(const char *device, 
					const char *password, 
					size_t passwordLen, 
					struct luks_phdr *hdr, 
					struct luks_masterkey **mk,
					struct setup_backend *backend);


int LUKS_del_key(const char *device, unsigned int keyIndex);
int LUKS_is_last_keyslot(const char *device, unsigned int keyIndex);
int LUKS_benchmarkt_iterations();

int LUKS_encrypt_to_storage(char *src, size_t srcLength,
			    struct luks_phdr *hdr,
			    char *key, size_t keyLength,
			    const char *device,
			    unsigned int sector, struct setup_backend *backend);
	
int LUKS_decrypt_from_storage(char *dst, size_t dstLength,
			      struct luks_phdr *hdr,
			      char *key, size_t keyLength,
			      const char *device,
			      unsigned int sector, struct setup_backend *backend);
int LUKS_device_ready(const char *device, int mode);
#endif
