/*
 * UTF8/16 helpers, copied and adapted from systemd project.
 *
 * Copyright (C) 2010 Lennart Poettering
 *
 * cryptsetup related changes
 * Copyright (C) 2021-2024 Vojtech Trefny

 * Parts of the original systemd implementation are based on the GLIB utf8
 * validation functions.
 * gutf8.c - Operations on UTF-8 strings.
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <errno.h>
#include <endian.h>

#include "crypto_backend.h"

static inline bool utf16_is_surrogate(char16_t c)
{
	return c >= 0xd800U && c <= 0xdfffU;
}

static inline bool utf16_is_trailing_surrogate(char16_t c)
{
	return c >= 0xdc00U && c <= 0xdfffU;
}

static inline char32_t utf16_surrogate_pair_to_unichar(char16_t lead, char16_t trail)
{
	return ((((char32_t) lead - 0xd800U) << 10) + ((char32_t) trail - 0xdc00U) + 0x10000U);
}

/**
 * utf8_encode_unichar() - Encode single UCS-4 character as UTF-8
 * @out_utf8: output buffer of at least 4 bytes or NULL
 * @g: UCS-4 character to encode
 *
 * This encodes a single UCS-4 character as UTF-8 and writes it into @out_utf8.
 * The length of the character is returned. It is not zero-terminated! If the
 * output buffer is NULL, only the length is returned.
 *
 * Returns: The length in bytes that the UTF-8 representation does or would
 *          occupy.
 */
static size_t utf8_encode_unichar(char *out_utf8, char32_t g)
{
	if (g < (1 << 7)) {
		if (out_utf8)
			out_utf8[0] = g & 0x7f;
		return 1;
	} else if (g < (1 << 11)) {
		if (out_utf8) {
			out_utf8[0] = 0xc0 | ((g >> 6) & 0x1f);
			out_utf8[1] = 0x80 | (g & 0x3f);
		}
		return 2;
	} else if (g < (1 << 16)) {
		if (out_utf8) {
			out_utf8[0] = 0xe0 | ((g >> 12) & 0x0f);
			out_utf8[1] = 0x80 | ((g >> 6) & 0x3f);
			out_utf8[2] = 0x80 | (g & 0x3f);
		}
		return 3;
	} else if (g < (1 << 21)) {
		if (out_utf8) {
			out_utf8[0] = 0xf0 | ((g >> 18) & 0x07);
			out_utf8[1] = 0x80 | ((g >> 12) & 0x3f);
			out_utf8[2] = 0x80 | ((g >> 6) & 0x3f);
			out_utf8[3] = 0x80 | (g & 0x3f);
		}
		return 4;
	}

	return 0;
}

/**
 * crypt_utf16_to_utf8()
 * @out: output buffer, should be 2 * @length + 1 long
 * @s: string to convert
 * @length: length of @s in bytes
 *
 * Converts a UTF16LE encoded string to a UTF8 encoded string.
 *
 * Returns: 0 on success, negative errno otherwise
 */
int crypt_utf16_to_utf8(char **out, const char16_t *s, size_t length /* bytes! */)
{
	const uint8_t *f;
	char *t;

	assert(s);
	assert(out);
	assert(*out);

	/* Input length is in bytes, i.e. the shortest possible character takes 2 bytes. Each unicode character may
	 * take up to 4 bytes in UTF-8. Let's also account for a trailing NUL byte. */
	if (length * 2 < length)
		return -EOVERFLOW; /* overflow */

	f = (const uint8_t*) s;
	t = *out;

	while (f + 1 < (const uint8_t*) s + length) {
		char16_t w1, w2;

		/* see RFC 2781 section 2.2 */

		w1 = f[1] << 8 | f[0];
		f += 2;

		if (!utf16_is_surrogate(w1)) {
			t += utf8_encode_unichar(t, w1);
			continue;
		}

		if (utf16_is_trailing_surrogate(w1))
			continue; /* spurious trailing surrogate, ignore */

		if (f + 1 >= (const uint8_t*) s + length)
			break;

		w2 = f[1] << 8 | f[0];
		f += 2;

		if (!utf16_is_trailing_surrogate(w2)) {
			f -= 2;
			continue; /* surrogate missing its trailing surrogate, ignore */
		}

		t += utf8_encode_unichar(t, utf16_surrogate_pair_to_unichar(w1, w2));
	}

	*t = 0;
	return 0;
}

/* count of characters used to encode one unicode char */
static size_t utf8_encoded_expected_len(uint8_t c)
{
	if (c < 0x80)
		return 1;
	if ((c & 0xe0) == 0xc0)
		return 2;
	if ((c & 0xf0) == 0xe0)
		return 3;
	if ((c & 0xf8) == 0xf0)
		return 4;
	if ((c & 0xfc) == 0xf8)
		return 5;
	if ((c & 0xfe) == 0xfc)
		return 6;

	return 0;
}

/* decode one unicode char */
static int utf8_encoded_to_unichar(const char *str, char32_t *ret_unichar)
{
	char32_t unichar;
	size_t len, i;

	assert(str);

	len = utf8_encoded_expected_len(str[0]);

	switch (len) {
	case 1:
		*ret_unichar = (char32_t)str[0];
		return 0;
	case 2:
		unichar = str[0] & 0x1f;
		break;
	case 3:
		unichar = (char32_t)str[0] & 0x0f;
		break;
	case 4:
		unichar = (char32_t)str[0] & 0x07;
		break;
	case 5:
		unichar = (char32_t)str[0] & 0x03;
		break;
	case 6:
		unichar = (char32_t)str[0] & 0x01;
		break;
	default:
		return -EINVAL;
	}

	for (i = 1; i < len; i++) {
		if (((char32_t)str[i] & 0xc0) != 0x80)
			return -EINVAL;

		unichar <<= 6;
		unichar |= (char32_t)str[i] & 0x3f;
	}

	*ret_unichar = unichar;

	return 0;
}

static size_t utf16_encode_unichar(char16_t *out, char32_t c)
{
	/* Note that this encodes as little-endian. */

	switch (c) {

	case 0 ... 0xd7ffU:
	case 0xe000U ... 0xffffU:
		out[0] = htole16(c);
		return 1;

	case 0x10000U ... 0x10ffffU:
		c -= 0x10000U;
		out[0] = htole16((c >> 10) + 0xd800U);
		out[1] = htole16((c & 0x3ffU) + 0xdc00U);
		return 2;

	default: /* A surrogate (invalid) */
		return 0;
	}
}

/**
 * crypt_utf8_to_utf16()
 * @out: output buffer, should be @length + 1 long
 * @s: string to convert
 * @length: length of @s in bytes
 *
 * Converts a UTF8 encoded string to a UTF16LE encoded string.
 *
 * Returns: 0 on success, negative errno otherwise
 */
int crypt_utf8_to_utf16(char16_t **out, const char *s, size_t length)
{
	char16_t *p;
	size_t i;
	int r;

	assert(s);

	p = *out;

	for (i = 0; i < length;) {
		char32_t unichar;
		size_t e;

		e = utf8_encoded_expected_len(s[i]);
		if (e <= 1) /* Invalid and single byte characters are copied as they are */
			goto copy;

		if (i + e > length) /* sequence longer than input buffer, then copy as-is */
			goto copy;

		r = utf8_encoded_to_unichar(s + i, &unichar);
		if (r < 0) /* sequence invalid, then copy as-is */
			goto copy;

		p += utf16_encode_unichar(p, unichar);
		i += e;
		continue;

	copy:
		*(p++) = htole16(s[i++]);
	}

	*p = 0;
	return 0;
}
