#include <libcryptsetup.h>
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypt_examples.h"

#define LOG_PREFIX_CD	"cslog_example_prefix"

int log_ready = 0;

/*
 * This is an example of function that can be registered using crypt_set_log_callback API.
 *
 * Its prototype is void (*log)(int level, const char *msg, void *usrptr) as defined
 * in crypt_set_log_callback
 *
 * NOTE: that some syslog message levels may not be visible with respect to your
 * 	 syslog setings
 *
 * 	 If your syslog daemon is turned off, messages should be printed to stderr
 */
static void simple_syslog_wrapper(int level, const char *msg, void *usrptr)
{
	if(!log_ready) {
		openlog((char *)usrptr, LOG_CONS | LOG_PID, LOG_USER);
		log_ready = 1;
	}
	switch(level) {
		case CRYPT_LOG_NORMAL:
			syslog(LOG_NOTICE, msg);
			break;
		case CRYPT_LOG_ERROR:
			syslog(LOG_ERR, msg);
			break;
		case CRYPT_LOG_VERBOSE:
			syslog(LOG_INFO, msg);
			break;
		case CRYPT_LOG_DEBUG:
			syslog(LOG_DEBUG, msg);
			break;
		default:
			fprintf(stderr, "Unsupported log level requested!\n");
	}
}

int main(void)
{
	int step = 0, r = 0;
	struct crypt_device *cd;

	if (geteuid())
		fprintf(stderr, "WARN: Process doesn't have super user privileges. "
				"Most of examples will fail because of that.\n");

	EX_STEP(++step, "crypt_init() to get an empty device context");
	if ((r = crypt_init(&cd, NULL))) {
		EX_FAIL("crypt_init() failed.");
		return r;
	}
	EX_SUCCESS("crypt_init() successfull");

	EX_STEP(++step, "crypt_set_log_callback() to register a log function tied with context");
	crypt_set_log_callback(cd, &simple_syslog_wrapper, LOG_PREFIX_CD);
	EX_SUCCESS("");
	EX_DELIM;

	EX_STEP(++step, "multiple crypt_log() to send messages into the context set log function. "
			"The messages should be prefixed with '" LOG_PREFIX_CD "'");
	crypt_log(cd, CRYPT_LOG_NORMAL, "This is normal log message");
	crypt_log(cd, CRYPT_LOG_ERROR, "This is error log message");
	crypt_log(cd, CRYPT_LOG_VERBOSE, "This is verbose log message");
	crypt_log(cd, CRYPT_LOG_DEBUG, "This is debug message");
	EX_SUCCESS("");
	EX_DELIM;

	crypt_free(cd);

	if (log_ready)
		closelog();

	log_ready = 0;

	EX_STEP(++step, "crypt_set_log_callback() to register a default (global) log function");
	crypt_set_log_callback(NULL, &simple_syslog_wrapper, NULL);
	EX_SUCCESS("");
	EX_DELIM;

	EX_STEP(++step, "multiple crypt_log() to send messages into default log");
	crypt_log(NULL, CRYPT_LOG_NORMAL, "This is normal log message");
	crypt_log(NULL, CRYPT_LOG_ERROR, "This is error log message");
	crypt_log(NULL, CRYPT_LOG_VERBOSE, "This is verbose log message");
	crypt_log(NULL, CRYPT_LOG_DEBUG, "This is debug message");
	EX_SUCCESS("");

	return r;
}
