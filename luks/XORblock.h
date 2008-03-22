#ifndef INCLUDED_CRYPTSETUP_LUKS_XORBLOCK_H
#define INCLUDED_CRYPTSETUP_LUKS_XORBLOCK_H

#include <stddef.h>

static void inline XORblock(char const *src1, char const *src2, char *dst, size_t n)
{
	size_t j;
	for(j = 0; j < n; ++j)
		dst[j] = src1[j] ^ src2[j];
}

#endif
