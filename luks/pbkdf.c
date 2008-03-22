/*
 * Copyright 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Implementation of PBKDF2-HMAC-SHA1 according to RFC 2898.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
 
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>

#include "hmac_sha1.h"
#include "XORblock.h"
#include <assert.h>

static unsigned int *__PBKDF2_global_j;
static unsigned int __PBKDF2_performance=0;

void PBKDF2_HMAC_SHA1(const char *password, size_t passwordLen, 
		      const char *salt, size_t saltLen, unsigned int iterations, 
		      char *dKey, size_t dKeyLen)
{
	uint32_t i=1;
	unsigned int j;
	/* U_n is the buffer for U_n values */
	unsigned char U_n[SHA1_DIGEST_SIZE];
	/* F_buf is the XOR buffer for F function */
	char F_buf[SHA1_DIGEST_SIZE];
	hmac_ctx templateCtx;

	/* We need a global pointer for signal handlers */
	__PBKDF2_global_j = &j;

	/* Make a template context initialized with password as key */
	hmac_sha_begin(&templateCtx);
	hmac_sha_key((unsigned char *) password,passwordLen,&templateCtx);
	
#define HMAC_REINIT(__ctx)		memcpy(&__ctx,&templateCtx,sizeof(__ctx))
	
	/* The first hash iteration is done different, therefor 
		we reduce iterations to conveniently use it as a loop 
		counter */
	assert(iterations != 0);
	iterations--; 

	while(dKeyLen > 0) {
		hmac_ctx ctx;
		uint32_t iNetworkOrdered;
		unsigned int blocksize = dKeyLen<SHA1_DIGEST_SIZE?dKeyLen:SHA1_DIGEST_SIZE;

		j=iterations;
		HMAC_REINIT(ctx);
		// U_1 hashing 
		hmac_sha_data((unsigned char *) salt,saltLen,&ctx);
		iNetworkOrdered = htonl(i);
		hmac_sha_data((unsigned char *)&iNetworkOrdered, sizeof(uint32_t), &ctx);
		hmac_sha_end(U_n, SHA1_DIGEST_SIZE, &ctx);
		memcpy(F_buf, U_n, SHA1_DIGEST_SIZE);

		// U_n hashing
		while(j--) {
			HMAC_REINIT(ctx);
			hmac_sha_data(U_n,SHA1_DIGEST_SIZE, &ctx);
			hmac_sha_end(U_n,SHA1_DIGEST_SIZE, &ctx);
			XORblock(F_buf,(char*) U_n,F_buf,SHA1_DIGEST_SIZE);
		}
		memcpy(dKey,F_buf,blocksize);
		dKey+=blocksize; dKeyLen-=blocksize; i++;
	}
#undef HMAC_REINIT
}

static void sigvtalarm(int foo)
{
	__PBKDF2_performance = ~(0U) - *__PBKDF2_global_j;
	*__PBKDF2_global_j = 0;
}

unsigned int PBKDF2_performance_check() 
{
	/* This code benchmarks PBKDF2 and returns 
	iterations/second per SHA1_DIGEST_SIZE */
	
	char buf;
	struct itimerval it;

	if(__PBKDF2_performance != 0) return __PBKDF2_performance;

	signal(SIGVTALRM,sigvtalarm);
	it.it_interval.tv_usec = 0;
	it.it_interval.tv_sec = 0;
	it.it_value.tv_usec = 0;
	it.it_value.tv_sec =  1;
	if (setitimer (ITIMER_VIRTUAL, &it, NULL) < 0)
	return 0;

	PBKDF2_HMAC_SHA1("foo", 3,
			 "bar", 3, ~(0U),
			 &buf, 1);
	
	return __PBKDF2_performance;
}
