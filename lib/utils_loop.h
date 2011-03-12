#ifndef _UTILS_LOOP_H
#define _UTILS_LOOP_H

/* loopback device helpers */

#define LOOP_DEV_MAJOR 7

char *crypt_loop_get_device(void);
char *crypt_loop_backing_file(const char *loop);
int crypt_loop_device(const char *loop);
int crypt_loop_attach(const char *loop, const char *file, int offset, int *readonly);

#endif /* _UTILS_CRYPT_H */
