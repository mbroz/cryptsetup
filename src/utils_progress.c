// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * cryptsetup - progress output utilities
 *
 * Copyright (C) 2009-2025 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2009-2025 Milan Broz
 */

#include <assert.h>
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

static bool calculate_tdiff(bool final, uint64_t bytes, struct tools_progress_params *parms, double *r_tdiff)
{
	uint64_t frequency;
	struct timeval now_time;

	assert(r_tdiff);

	gettimeofday(&now_time, NULL);
	if (parms->start_time.tv_sec == 0 && parms->start_time.tv_usec == 0) {
		parms->start_time = now_time;
		parms->end_time = now_time;
		parms->start_offset = bytes;
		return false;
	}

	if (parms->frequency)
		frequency = parms->frequency * UINT64_C(1000000);
	else
		frequency = 500000;

	if (!final && time_diff(&parms->end_time, &now_time) < frequency)
		return false;

	parms->end_time = now_time;

	*r_tdiff = time_diff(&parms->start_time, &parms->end_time) / 1E6;
	if (!*r_tdiff)
		return false;

	return true;
}

static void tools_time_progress(uint64_t device_size, uint64_t bytes, struct tools_progress_params *parms)
{
	uint64_t eta;
	double tdiff, uib;
	const char *eol, *ustr;
	bool final = (bytes == device_size);

	if (!calculate_tdiff(final, bytes, parms, &tdiff))
		return;

	if (parms->frequency)
		eol = "\n";
	else
		eol = "";

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

static void log_progress_json(const char *device, uint64_t bytes, uint64_t device_size, uint64_t eta, uint64_t uib, uint64_t time_spent)
{
	int r;
	char json[PATH_MAX+256];

	r = snprintf(json, sizeof(json) - 1,
		     "{\"device\":\"%s\","
		     "\"device_bytes\":\"%"	PRIu64 "\","	/* in bytes */
		     "\"device_size\":\"%"	PRIu64 "\","	/* in bytes */
		     "\"speed\":\"%"		PRIu64 "\","	/* in bytes per second */
		     "\"eta_ms\":\"%"		PRIu64 "\","	/* in milliseconds */
		     "\"time_ms\":\"%"		PRIu64 "\"}\n",	/* in milliseconds */
		     device, bytes, device_size, uib, eta, time_spent);

	if (r < 0 || (size_t)r >= sizeof(json) - 1)
		return;

	log_std("%s", json);
}

static void tools_time_progress_json(uint64_t device_size, uint64_t bytes, struct tools_progress_params *parms)
{
	double tdiff, uib;
	bool final = (bytes == device_size);

	if (!calculate_tdiff(final, bytes, parms, &tdiff))
		return;

	uib = (double)(bytes - parms->start_offset) / tdiff;

	log_progress_json(parms->device,
			  bytes,
			  device_size,
			  final ? UINT64_C(0) : (uint64_t)((device_size / uib - tdiff) * 1E3),
			  (uint64_t)uib,
			  (uint64_t)(tdiff * 1E3));

	fflush(stdout);
}

int tools_progress(uint64_t size, uint64_t offset, void *usrptr)
{
	int r = 0;
	struct tools_progress_params *parms = (struct tools_progress_params *)usrptr;

	if (parms && parms->json_output)
		tools_time_progress_json(size, offset, parms);
	else if (parms && !parms->batch_mode)
		tools_time_progress(size, offset, parms);

	check_signal(&r);
	if (r) {
		if (!parms || (!parms->frequency && !parms->json_output))
			tools_clear_line();
		if (parms && parms->interrupt_message)
			log_err("%s", parms->interrupt_message);
	}

	return r;
}

const char *tools_get_device_name(const char *device, char **r_backing_file)
{
	char *bfile;

	assert(r_backing_file);

	bfile = crypt_loop_backing_file(device);
	if (bfile) {
		*r_backing_file = bfile;
		return bfile;
	}

	return device;
}
