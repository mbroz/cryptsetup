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

#define MINUTES_90 UINT64_C(5400000000)   /* 90 minutes in microseconds */
#define HOURS_36   UINT64_C(129600000000) /* 36 hours in microseconds */

#define MINUTES(A) (A) / UINT64_C(60000000)    /* microseconds to minutes */
#define SECONDS(A) (A) / UINT64_C(1000000)     /* microseconds to seconds */
#define HOURS(A)   (A) / UINT64_C(3600000000)  /* microseconds to hours */
#define DAYS(A)    (A) / UINT64_C(86400000000) /* microseconds to days */

#define REMAIN_SECONDS(A) (SECONDS((A))) % 60
#define REMAIN_MINUTES(A) (MINUTES((A))) % 60

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

static void bytes_to_units(uint64_t *bytes, const char **units)
{
	if (*bytes < (UINT64_C(1) << 32)) { /* less than 4 GiBs */
		*units = "MiB";
		*bytes >>= 20;
	} else if (*bytes < (UINT64_C(1) << 42)) { /* less than 4 TiBs */
		*units = "GiB";
		*bytes >>= 30;
	} else if (*bytes < (UINT64_C(1) << 52)) { /* less than 4 PiBs */
		*units = "TiB";
		*bytes >>= 40;
	} else if (*bytes < (UINT64_C(1) << 62)) { /* less than 4 EiBs */
		*units = "PiB";
		*bytes >>= 50;
	} else {
		*units = "EiB";
		*bytes >>= 60;
	}
}

static bool time_to_human_string(uint64_t usecs, char *buf, size_t buf_len)
{
	ssize_t r;

	if (usecs < MINUTES_90)
		r = snprintf(buf, buf_len, _("%02" PRIu64 "m%02" PRIu64 "s"), MINUTES(usecs), REMAIN_SECONDS(usecs));
	else if (usecs < HOURS_36)
		r = snprintf(buf, buf_len, _("%02" PRIu64 "h%02" PRIu64 "m%02" PRIu64 "s"), HOURS(usecs), REMAIN_MINUTES(usecs), REMAIN_SECONDS(usecs));
	else
		r = snprintf(buf, buf_len, _("%02" PRIu64 " days"), DAYS(usecs));

	if (r < 0 || (size_t)r >= buf_len)
		return false;

	return true;
}

static void log_progress(uint64_t bytes, uint64_t device_size, uint64_t eta, double uib, const char *ustr, const char *eol)
{
	double progress;
	int r;
	const char *units;
	char time[128], written[128], speed[128];

	/*
	 * TRANSLATORS: 'time' string with examples:
	 * "12m44s"    : meaning 12 minutes 44 seconds
	 * "26h12m44s" : meaning 26 hours 12 minutes 44 seconds
	 * "3 days"
	 */
	if (!time_to_human_string(eta, time, sizeof(time)))
		return;

	progress = (double)bytes / device_size * 100.0;

	bytes_to_units(&bytes, &units);
	r = snprintf(written, sizeof(written), _("%4" PRIu64 " %s written"), bytes, units);
	if (r < 0 || (size_t)r >= sizeof(written))
		return;

	r = snprintf(speed, sizeof(speed), _("speed %5.1f %s/s"), uib, ustr);
	if (r < 0 || (size_t)r >= sizeof(speed))
		return;

	/*
	 * TRANSLATORS: 'time', 'written' and 'speed' string are supposed
	 * to get translated as well. 'eol' is always new-line or empty.
	 * See above.
	 */
	log_std(_("Progress: %5.1f%%, ETA %s, %s, %s%s"),
		progress, time, written, speed, eol);
}

static void log_progress_final(uint64_t time_spent, uint64_t bytes, double uib, const char *ustr)
{
	int r;
	const char *units;
	char time[128], written[128], speed[128];

	/*
	 * TRANSLATORS: 'time' string with examples:
	 * "12m44s"    : meaning 12 minutes 44 seconds
	 * "26h12m44s" : meaning 26 hours 12 minutes 44 seconds
	 * "3 days"
	 */
	if (!time_to_human_string(time_spent, time, sizeof(time)))
		return;

	bytes_to_units(&bytes, &units);
	r = snprintf(written, sizeof(written) - 1, _("%4" PRIu64 " %s written"), bytes, units);
	if (r < 0 || (size_t)r >= sizeof(written))
		return;

	r = snprintf(speed, sizeof(speed) - 1, _("speed %5.1f %s/s"), uib, ustr);
	if (r < 0 || (size_t)r >= sizeof(speed))
		return;

	/*
	 * TRANSLATORS: 'time', 'written' and 'speed' string are supposed
	 * to get translated as well. See above
	 */
	log_std(_("Finished, time %s, %s, %s\n"), time, written, speed);
}

static void tools_time_progress(uint64_t device_size, uint64_t bytes, struct tools_progress_params *parms)
{
	struct timeval now_time;
	uint64_t eta, frequency;
	double tdiff, uib;
	const char *eol, *ustr;
	bool final = (bytes == device_size);

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

	uib = (double)(bytes - parms->start_offset) / tdiff;

	eta = (uint64_t)((device_size / uib - tdiff) * 1E6);

	if (uib > 1073741824.0f) {
		uib /= 1073741824.0f;
		ustr = "GiB";
	} else if (uib > 1048576.0f) {
		uib /= 1048576.0f;
		ustr = "MiB";
	} else if (uib > 1024.0f) {
		uib /= 1024.0f;
		ustr = "KiB";
	} else
		ustr = "B";

	if (!parms->frequency)
		tools_clear_line();

	if (final)
		log_progress_final((uint64_t)(tdiff * 1E6), bytes, uib, ustr);
	else
		log_progress(bytes, device_size, eta, uib, ustr, eol);

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
