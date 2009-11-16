#ifndef CRYPTSETUP_H
#define CRYPTSETUP_H

#ifdef HAVE_CONFIG_H
#	include <config.h>
#endif

#include "lib/nls.h"

#define DEFAULT_CIPHER		"aes"
#define DEFAULT_LUKS_CIPHER     "aes-cbc-essiv:sha256"
#define DEFAULT_HASH		"ripemd160"
#define DEFAULT_LUKS_HASH	"sha1"
#define DEFAULT_KEY_SIZE	256
#define DEFAULT_LUKS_KEY_SIZE	128

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"32"

#define log_dbg(x...) clogger(NULL, CRYPT_LOG_DEBUG, __FILE__, __LINE__, x)
#define log_std(x...) clogger(NULL, CRYPT_LOG_NORMAL, __FILE__, __LINE__, x)
#define log_err(x...) clogger(NULL, CRYPT_LOG_ERROR, __FILE__, __LINE__, x)

#endif /* CRYPTSETUP_H */
