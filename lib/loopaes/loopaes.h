#ifndef _LOOPAES_H
#define _LOOPAES_H

#define LOOPAES_KEYS_MAX 65
#define LOOPAES_KEYFILE_MINSIZE 60
#define LOOPAES_KEYFILE_MAXSIZE 16000

int LOOPAES_parse_keyfile(struct crypt_device *cd,
			  struct volume_key **vk,
			  unsigned int *keys_count,
			  char *buffer,
			  unsigned int buffer_len);

int LOOPAES_activate(struct crypt_device *cd,
		     const char *name,
		     const char *base_cipher,
		     unsigned int keys_count,
		     struct volume_key *vk,
		     uint32_t flags);
#endif
