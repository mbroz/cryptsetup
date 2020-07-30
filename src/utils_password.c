/*
 * Password quality check wrapper
 *
 * Copyright (C) 2012-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2020 Milan Broz
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "cryptsetup.h"

void tools_passphrase_msg(int r)
{
	if (r == -EPERM)
		log_err(_("No key available with this passphrase."));
	else if (r == -ENOENT)
		log_err(_("No usable keyslot is available."));
}

/*
 * Only tool that currently blocks signals explicitely is cryptsetup-reencrypt.
 * Leave the tools_get_key stub with signals handling here and remove it later
 * only if we find signals blocking obsolete.
 */
int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  uint64_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd)
{
	int r, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	r = crypt_cli_get_key(prompt, key, key_size, keyfile_offset,
		keyfile_size_max, key_file, timeout, verify, pwquality, cd, NULL);

	if (block && !quit)
		set_int_block(1);

	return r;
}
