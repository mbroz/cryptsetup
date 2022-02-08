/*
 * cryptsetup - progress output utilities
 *
 * Copyright (C) 2009-2022 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2022 Milan Broz
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
#include <math.h>

/* The difference in microseconds between two times in "timeval" format. */
static uint64_t time_diff(struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec) * UINT64_C(1000000)
		+ (end->tv_usec - start->tv_usec);
}

static void tools_clear_line(void)
{
	/* vt100 code clear line */
	log_std("\33[2K\r");
}

static void tools_time_progress(uint64_t device_size, uint64_t bytes, struct tools_progress_params *parms)
{
	struct timeval now_time;
	uint64_t mbytes, eta, frequency;
	double tdiff, uib;
	int final = (bytes == device_size);
	const char *eol, *ustr = "";

	gettimeofday(&now_time, NULL);
	if (parms->start_time.tv_sec == 0 && parms->start_time.tv_usec == 0) {
		parms->start_time = now_time;
		parms->end_time = now_time;
		parms->start_offset = bytes;
		return;
	}

	if (parms->frequency) {
		frequency = parms->frequency * UINT64_C(1000000);
		eol = "\n";
	} else {
		frequency = 500000;
		eol = "";
	}

	if (!final && time_diff(&parms->end_time, &now_time) < frequency)
		return;

	parms->end_time = now_time;

	tdiff = time_diff(&parms->start_time, &parms->end_time) / 1E6;
	if (!tdiff)
		return;

	mbytes = bytes  / 1024 / 1024;
	uib = (double)(bytes - parms->start_offset) / tdiff;

	eta = (uint64_t)(device_size / uib - tdiff);

	if (uib > 1073741824.0f) {
		uib /= 1073741824.0f;
		ustr = "Gi";
	} else if (uib > 1048576.0f) {
		uib /= 1048576.0f;
		ustr = "Mi";
	} else if (uib > 1024.0f) {
		uib /= 1024.0f;
		ustr = "Ki";
	}

	if (!parms->frequency)
		tools_clear_line();
	if (final)
		log_std("Finished, time %02" PRIu64 ":%02" PRIu64 ".%03" PRIu64 ", "
			"%4" PRIu64 " MiB written, speed %5.1f %sB/s\n",
			(uint64_t)tdiff / 60,
			(uint64_t)tdiff % 60,
			(uint64_t)((tdiff - floor(tdiff)) * 1000.0),
			mbytes, uib, ustr);
	else
		log_std("Progress: %5.1f%%, ETA %02llu:%02llu, "
			"%4llu MiB written, speed %5.1f %sB/s%s",
			(double)bytes / device_size * 100,
			eta / 60, eta % 60, mbytes, uib, ustr, eol);
	fflush(stdout);
}

int tools_wipe_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	int r = 0;
	struct tools_progress_params *parms = (struct tools_progress_params *)usrptr;

	if (parms && !parms->batch_mode)
		tools_time_progress(size, offset, parms);

	check_signal(&r);
	if (r) {
		if (!parms || !parms->frequency)
			tools_clear_line();
		log_err(_("\nWipe interrupted."));
	}

	return r;
}

int tools_reencrypt_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	int r = 0;
	struct tools_progress_params *parms = (struct tools_progress_params *)usrptr;

	if (parms && !parms->batch_mode)
		tools_time_progress(size, offset, parms);

	check_signal(&r);
	if (r) {
		if (!parms || !parms->frequency)
			tools_clear_line();
		log_err(_("\nReencryption interrupted."));
	}

	return r;
}
