#ifndef _CRYPTO_BACKEND_H
#define _CRYPTO_BACKEND_H

#include "libcryptsetup.h"
#include "internal.h"

struct crypt_hash;
struct crypt_hmac;

int crypt_backend_init(struct crypt_device *ctx);

#define CRYPT_BACKEND_KERNEL (1 << 0)	/* Crypto uses kernel part, for benchmark */

uint32_t crypt_backend_flags(void);

/* HASH */
int crypt_hash_size(const char *name);
int crypt_hash_init(struct crypt_hash **ctx, const char *name);
int crypt_hash_write(struct crypt_hash *ctx, const char *buffer, size_t length);
int crypt_hash_final(struct crypt_hash *ctx, char *buffer, size_t length);
int crypt_hash_destroy(struct crypt_hash *ctx);

/* HMAC */
int crypt_hmac_size(const char *name);
int crypt_hmac_init(struct crypt_hmac **ctx, const char *name,
		    const void *buffer, size_t length);
int crypt_hmac_write(struct crypt_hmac *ctx, const char *buffer, size_t length);
int crypt_hmac_final(struct crypt_hmac *ctx, char *buffer, size_t length);
int crypt_hmac_destroy(struct crypt_hmac *ctx);

#endif /* _CRYPTO_BACKEND_H */
