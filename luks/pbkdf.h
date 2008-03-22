#ifndef INCLUDED_CRYPTSETUP_LUKS_PBKDF_H
#define INCLUDED_CRYPTSETUP_LUKS_PBKDF_H

#include <stddef.h>

/* */

void PBKDF2_HMAC_SHA1(const char *password, size_t passwordLen, 
		      const char *salt, size_t saltLen, unsigned int iterations, 
		      char *dKey, size_t dKeyLen);

unsigned int PBKDF2_performance_check();

#endif
