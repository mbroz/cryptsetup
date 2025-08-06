// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Base64 "Not encryption" helpers, copied and adapted from systemd project.
 *
 * Copyright (C) 2010 Lennart Poettering
 *
 * cryptsetup related changes
 * Copyright (C) 2021-2025 Milan Broz
 */

#include <errno.h>
#include <stdlib.h>
#include <limits.h>

#include "crypto_backend.h"

#define WHITESPACE " \t\n\r"

/* https://tools.ietf.org/html/rfc4648#section-4 */
static char base64char(int x)
{
	static const char table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
				      "abcdefghijklmnopqrstuvwxyz"
				      "0123456789+/";
	return table[x & 63];
}

static int unbase64char(char c)
{
	unsigned offset;

	if (c >= 'A' && c <= 'Z')
		return c - 'A';

	offset = 'Z' - 'A' + 1;

	if (c >= 'a' && c <= 'z')
		return c - 'a' + offset;

	offset += 'z' - 'a' + 1;

	if (c >= '0' && c <= '9')
		return c - '0' + offset;

	offset += '9' - '0' + 1;

	if (c == '+')
		return offset;

	offset++;

	if (c == '/')
		return offset;

	return -EINVAL;
}

int crypt_base64_encode(char **out, size_t *out_length, const char *in, size_t in_length)
{
	char *r, *z;
	const uint8_t *x;

	assert(in || in_length == 0);
	assert(out);

	/* three input bytes makes four output bytes, padding is added so we must round up */
	z = r = malloc(4 * (in_length + 2) / 3 + 1);
	if (!r)
		return -ENOMEM;

	for (x = (const uint8_t *)in; x < (const uint8_t*)in + (in_length / 3) * 3; x += 3) {
		/* x[0] == XXXXXXXX; x[1] == YYYYYYYY; x[2] == ZZZZZZZZ */
		*(z++) = base64char(x[0] >> 2);                    /* 00XXXXXX */
		*(z++) = base64char((x[0] & 3) << 4 | x[1] >> 4);  /* 00XXYYYY */
		*(z++) = base64char((x[1] & 15) << 2 | x[2] >> 6); /* 00YYYYZZ */
		*(z++) = base64char(x[2] & 63);                    /* 00ZZZZZZ */
	}

	switch (in_length % 3) {
	case 2:
		*(z++) = base64char(x[0] >> 2);                   /* 00XXXXXX */
		*(z++) = base64char((x[0] & 3) << 4 | x[1] >> 4); /* 00XXYYYY */
		*(z++) = base64char((x[1] & 15) << 2);            /* 00YYYY00 */
		*(z++) = '=';

		break;
	case 1:
		*(z++) = base64char(x[0] >> 2);        /* 00XXXXXX */
		*(z++) = base64char((x[0] & 3) << 4);  /* 00XX0000 */
		*(z++) = '=';
		*(z++) = '=';

		break;
	}

	*z = 0;
	*out = r;
	if (out_length)
		*out_length = z - r;
	return 0;
}

static int unbase64_next(const char **p, size_t *l)
{
	int ret;

	assert(p);
	assert(l);

	/* Find the next non-whitespace character, and decode it. If we find padding, we return it as INT_MAX. We
	 * greedily skip all preceding and all following whitespace. */

	for (;;) {
		if (*l == 0)
			return -EPIPE;

		if (!strchr(WHITESPACE, **p))
			break;

		/* Skip leading whitespace */
		(*p)++, (*l)--;
	}

	if (**p == '=')
		ret = INT_MAX; /* return padding as INT_MAX */
	else {
		ret = unbase64char(**p);
		if (ret < 0)
			return ret;
	}

	for (;;) {
		(*p)++, (*l)--;

		if (*l == 0)
			break;
		if (!strchr(WHITESPACE, **p))
			break;

		/* Skip following whitespace */
	}

	return ret;
}

int crypt_base64_decode(char **out, size_t *out_length, const char *in, size_t in_length)
{
	uint8_t *buf = NULL;
	const char *x;
	uint8_t *z;
	size_t len;
	int r;

	assert(in || in_length == 0);
	assert(out);
	assert(out_length);

	if (in_length == (size_t) -1)
		in_length = strlen(in);

	/* A group of four input bytes needs three output bytes, in case of padding we need to add two or three extra
	 * bytes. Note that this calculation is an upper boundary, as we ignore whitespace while decoding */
	len = (in_length / 4) * 3 + (in_length % 4 != 0 ? (in_length % 4) - 1 : 0);

	buf = malloc(len + 1);
	if (!buf)
		return -ENOMEM;

	for (x = in, z = buf;;) {
		int a, b, c, d; /* a == 00XXXXXX; b == 00YYYYYY; c == 00ZZZZZZ; d == 00WWWWWW */

		a = unbase64_next(&x, &in_length);
		if (a == -EPIPE) /* End of string */
			break;
		if (a < 0) {
			r = a;
			goto err;
		}
		if (a == INT_MAX) { /* Padding is not allowed at the beginning of a 4ch block */
			r = -EINVAL;
			goto err;
		}

		b = unbase64_next(&x, &in_length);
		if (b < 0) {
			r = b;
			goto err;
		}
		if (b == INT_MAX) { /* Padding is not allowed at the second character of a 4ch block either */
			r = -EINVAL;
			goto err;
		}

		c = unbase64_next(&x, &in_length);
		if (c < 0) {
			r = c;
			goto err;
		}

		d = unbase64_next(&x, &in_length);
		if (d < 0) {
			r = d;
			goto err;
		}

		if (c == INT_MAX) { /* Padding at the third character */

			if (d != INT_MAX) { /* If the third character is padding, the fourth must be too */
				r = -EINVAL;
				goto err;
			}

			/* b == 00YY0000 */
			if (b & 15) {
				r = -EINVAL;
				goto err;
			}

			if (in_length > 0) { /* Trailing rubbish? */
				r = -ENAMETOOLONG;
				goto err;
			}

			*(z++) = (uint8_t) a << 2 | (uint8_t) (b >> 4); /* XXXXXXYY */
			break;
		}

		if (d == INT_MAX) {
			/* c == 00ZZZZ00 */
			if (c & 3) {
				r = -EINVAL;
				goto err;
			}

			if (in_length > 0) { /* Trailing rubbish? */
				r = -ENAMETOOLONG;
				goto err;
			}

			*(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
			*(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
			break;
		}

		*(z++) = (uint8_t) a << 2 | (uint8_t) b >> 4; /* XXXXXXYY */
		*(z++) = (uint8_t) b << 4 | (uint8_t) c >> 2; /* YYYYZZZZ */
		*(z++) = (uint8_t) c << 6 | (uint8_t) d;      /* ZZWWWWWW */
	}

	*z = 0;

	*out_length = (size_t) (z - buf);
	*out = (char *)buf;
	return 0;
err:
	free(buf);

	/* Ignore other errors in crypt_backend */
	if (r != -ENOMEM)
		r = -EINVAL;

	return r;
}
