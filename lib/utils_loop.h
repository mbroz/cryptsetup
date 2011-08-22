#ifndef _UTILS_LOOP_H
#define _UTILS_LOOP_H

/* loopback device helpers */

#define LOOP_DEV_MAJOR 7

#ifndef LO_FLAGS_AUTOCLEAR
#define LO_FLAGS_AUTOCLEAR 4
#endif

#ifndef LOOP_CTL_GET_FREE
#define LOOP_CTL_GET_FREE 0x4C82
#endif

char *crypt_loop_get_device(void);
char *crypt_loop_backing_file(const char *loop);
int crypt_loop_device(const char *loop);
int crypt_loop_attach(const char *loop, const char *file, int offset,
		      int autoclear, int *readonly);
int crypt_loop_detach(const char *loop);

#endif /* _UTILS_LOOP_H */
