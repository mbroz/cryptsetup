#include <stdio.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include <libcryptsetup.h>

/*
 * This is an example of function that can be registered using crypt_set_log_callback API.
 *
 * Its prototype is void (*log)(int level, const char *msg, void *usrptr) as defined
 * in crypt_set_log_callback
 */
static void simple_syslog_wrapper(int level, const char *msg, void *usrptr)
{
	const char *prefix = (const char *)usrptr;
	int priority;

	switch(level) {
		case CRYPT_LOG_NORMAL:  priority = LOG_NOTICE; break;
		case CRYPT_LOG_ERROR:   priority = LOG_ERR;    break;
		case CRYPT_LOG_VERBOSE: priority = LOG_INFO;   break;
		case CRYPT_LOG_DEBUG:   priority = LOG_DEBUG;  break;
		default:
			fprintf(stderr, "Unsupported log level requested!\n");
			return;
	}

	if (prefix)
		syslog(priority, "%s:%s", prefix, msg);
	else
		syslog(priority, "%s", msg);
}

int main(void)
{
	struct crypt_device *cd;
	char usrprefix[] = "cslog_example";
	int r;

	if (geteuid()) {
		printf("Using of libcryptsetup requires super user privileges.\n");
		return 1;
	}

	openlog("cryptsetup", LOG_CONS | LOG_PID, LOG_USER);

	/* Initialize empty crypt device context */
	r = crypt_init(&cd, NULL);
	if (r < 0) {
		printf("crypt_init() failed.\n");
		return 2;
	}

	/* crypt_set_log_callback() - register a log function for crypt context */
	crypt_set_log_callback(cd, &simple_syslog_wrapper, (void *)usrprefix);

	/* send messages ithrough the crypt_log() interface */
	crypt_log(cd, CRYPT_LOG_NORMAL, "This is normal log message");
	crypt_log(cd, CRYPT_LOG_ERROR, "This is error log message");
	crypt_log(cd, CRYPT_LOG_VERBOSE, "This is verbose log message");
	crypt_log(cd, CRYPT_LOG_DEBUG, "This is debug message");

	/* release crypt context */
	crypt_free(cd);

	/* Initialize default (global) log function */
	crypt_set_log_callback(NULL, &simple_syslog_wrapper, NULL);

	crypt_log(NULL, CRYPT_LOG_NORMAL, "This is normal log message");
	crypt_log(NULL, CRYPT_LOG_ERROR, "This is error log message");
	crypt_log(NULL, CRYPT_LOG_VERBOSE, "This is verbose log message");
	crypt_log(NULL, CRYPT_LOG_DEBUG, "This is debug message");

	closelog();
	return 0;
}
