/*
 * Password quality check wrapper
 *
 * Copyright (C) 2012, Red Hat, Inc. All rights reserved.
 * Copyright (C) 2012-2014, Milan Broz
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

int opt_force_password = 0;

#if ENABLE_PWQUALITY
#include <pwquality.h>

static int tools_check_pwquality(const char *password)
{
	int r;
	void *auxerror;
	pwquality_settings_t *pwq; 

	log_dbg("Checking new password using default pwquality settings.");
	pwq = pwquality_default_settings();
	if (!pwq)
		return -EINVAL;

	r = pwquality_read_config(pwq, NULL, &auxerror);
	if (r) {
		log_err(_("Cannot check password quality: %s\n"),
			pwquality_strerror(NULL, 0, r, auxerror));
		pwquality_free_settings(pwq);
		return -EINVAL;
	}

	r = pwquality_check(pwq, password, NULL, NULL, &auxerror);
	if (r < 0) {
		log_err(_("Password quality check failed:\n %s\n"),
			pwquality_strerror(NULL, 0, r, auxerror));
		r = -EPERM;
	} else {
		log_dbg("New password libpwquality score is %d.", r);
		r = 0;
	}

	pwquality_free_settings(pwq);
	return r;
}
#else /* ENABLE_PWQUALITY */
static int tools_check_pwquality(const char *password)
{
	return 0;
}
#endif /* ENABLE_PWQUALITY */

int tools_get_key(const char *prompt,
		  char **key, size_t *key_size,
		  size_t keyfile_offset, size_t keyfile_size_max,
		  const char *key_file,
		  int timeout, int verify, int pwquality,
		  struct crypt_device *cd)
{
	int r, block;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	r = crypt_get_key(prompt, key, key_size, keyfile_offset,
			  keyfile_size_max, key_file, timeout, verify, cd);
	if (block && !quit)
		set_int_block(1);

	/* Check pwquality for password (not keyfile) */
	if (pwquality && !opt_force_password && !key_file && !r)
		r = tools_check_pwquality(*key);

	return r;
}
