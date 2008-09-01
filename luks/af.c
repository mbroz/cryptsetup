/*
 * AFsplitter - Anti forensic information splitter
 * Copyright 2004, Clemens Fruhwirth <clemens@endorphin.org>
 *
 * AFsplitter diffuses information over a large stripe of data, 
 * therefor supporting secure data destruction.
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
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include "sha1.h"
#include "XORblock.h"
#include "random.h"

/* diffuse: Information spreading over the whole dataset with
 * the help of sha512. 
 */

static void diffuse(unsigned char *src, unsigned char *dst, size_t size)
{
	sha1_ctx ctx;
	uint32_t i;
	uint32_t IV;	/* host byte order independend hash IV */
	
	unsigned int fullblocks = size / SHA1_DIGEST_SIZE;
	unsigned int padding = size % SHA1_DIGEST_SIZE;
	unsigned char final[SHA1_DIGEST_SIZE];

	/* hash block the whole data set with different IVs to produce
	 * more than just a single data block
	 */
	for (i=0; i < fullblocks; i++) {
		sha1_begin(&ctx);
		IV = htonl(i);
		sha1_hash((const unsigned char *) &IV, sizeof(IV), &ctx);
		sha1_hash(src + SHA1_DIGEST_SIZE * i, SHA1_DIGEST_SIZE, &ctx);
		sha1_end(dst + SHA1_DIGEST_SIZE * i, &ctx);
	}

	if(padding) {
		sha1_begin(&ctx);
		IV = htonl(i);
		sha1_hash((const unsigned char *) &IV, sizeof(IV), &ctx);
		sha1_hash(src + SHA1_DIGEST_SIZE * i, padding, &ctx);
		sha1_end(final, &ctx);
 		memcpy(dst + SHA1_DIGEST_SIZE * i, final, padding);
	}
}

/*
 * Information splitting. The amount of data is multiplied by
 * blocknumbers. The same blocksize and blocknumbers values 
 * must be supplied to AF_merge to recover information.
 */

int AF_split(char *src, char *dst, size_t blocksize, unsigned int blocknumbers)
{
	unsigned int i;
	char *bufblock;
	int r = -EINVAL;

	if((bufblock = calloc(blocksize, 1)) == NULL) return -ENOMEM;

	/* process everything except the last block */
	for(i=0; i<blocknumbers-1; i++) {
		r = getRandom(dst+(blocksize*i),blocksize);
		if(r < 0) goto out;

		XORblock(dst+(blocksize*i),bufblock,bufblock,blocksize);
		diffuse((unsigned char *) bufblock, (unsigned char *) bufblock, blocksize);
	}
	/* the last block is computed */
	XORblock(src,bufblock,dst+(i*blocksize),blocksize);
	r = 0;
out:
	free(bufblock);
	return r;
}

int AF_merge(char *src, char *dst, size_t blocksize, unsigned int blocknumbers)
{
	unsigned int i;
	char *bufblock;

	if((bufblock = calloc(blocksize, 1)) == NULL) return -ENOMEM;

	memset(bufblock,0,blocksize);
	for(i=0; i<blocknumbers-1; i++) {
		XORblock(src+(blocksize*i),bufblock,bufblock,blocksize);
		diffuse((unsigned char *) bufblock, (unsigned char *) bufblock, blocksize);
	}
	XORblock(src + blocksize * i, bufblock, dst, blocksize);

	free(bufblock);	
	return 0;
}
