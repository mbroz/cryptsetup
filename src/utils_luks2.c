/*
 * Helper utilities for LUKS2 features
 *
 * Copyright (C) 2018-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2018-2020 Milan Broz
 * Copyright (C) 2018-2020 Ondrej Kozina
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

/*
 * FIXME: 4MiBs is max LUKS2 mda length (including binary header).
 * In future, read max allowed JSON size from config section.
 */
#define LUKS2_MAX_MDA_SIZE 0x400000
int tools_read_json_file(struct crypt_device *cd, const char *file, char **json, size_t *json_size)
{
	ssize_t ret;
	int fd, block, r;
	void *buf = NULL;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (tools_is_stdin(file)) {
		fd = STDIN_FILENO;
		log_dbg("STDIN descriptor JSON read requested.");
	} else {
		log_dbg("File descriptor JSON read requested.");
		fd = open(file, O_RDONLY);
		if (fd < 0) {
			log_err(_("Failed to open file %s in read-only mode."), file);
			r = -EINVAL;
			goto out;
		}
	}

	buf = malloc(LUKS2_MAX_MDA_SIZE);
	if (!buf) {
		r = -ENOMEM;
		goto out;
	}

	if (isatty(fd) && !opt_batch_mode)
		log_std(_("Provide valid LUKS2 token JSON:\n"));

	/* we expect JSON (string) */
	r = 0;
	ret = read_buffer_intr(fd, buf, LUKS2_MAX_MDA_SIZE - 1, &quit);
	if (ret < 0) {
		r = -EIO;
		log_err(_("Failed to read JSON file."));
		goto out;
	}
	check_signal(&r);
	if (r) {
		log_err(_("\nRead interrupted."));
		goto out;
	}

	*json_size = (size_t)ret;
	*json = buf;
	*(*json + ret) = '\0';
out:
	if (block && !quit)
		set_int_block(1);
	if (fd >= 0 && fd != STDIN_FILENO)
		close(fd);
	if (r && buf) {
		memset(buf, 0, LUKS2_MAX_MDA_SIZE);
		free(buf);
	}
	return r;
}

int tools_write_json_file(struct crypt_device *cd, const char *file, const char *json)
{
	int block, fd, r;
	size_t json_len;
	ssize_t ret;

	if (!json || !(json_len = strlen(json)) || json_len >= LUKS2_MAX_MDA_SIZE)
		return -EINVAL;

	block = tools_signals_blocked();
	if (block)
		set_int_block(0);

	if (tools_is_stdin(file)) {
		fd = STDOUT_FILENO;
		log_dbg("STDOUT descriptor JSON write requested.");
	} else {
		log_dbg("File descriptor JSON write requested.");
		fd = open(file, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	}

	if (fd < 0) {
		log_err(_("Failed to open file %s in write mode."), file ?: "");
		r = -EINVAL;
		goto out;
	}

	r = 0;
	ret = write_buffer_intr(fd, json, json_len, &quit);
	check_signal(&r);
	if (r) {
		log_err(_("\nWrite interrupted."));
		goto out;
	}
	if (ret < 0 || (size_t)ret != json_len) {
		log_err(_("Failed to write JSON file."));
		r = -EIO;
		goto out;
	}

	if (isatty(fd))
		(void) write_buffer_intr(fd, "\n", 1, &quit);
out:
	if (block && !quit)
		set_int_block(1);
	if (fd >=0 && fd != STDOUT_FILENO)
		close(fd);
	return r;
}
