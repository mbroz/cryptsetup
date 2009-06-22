#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <termios.h>

#include "libcryptsetup.h"
#include "internal.h"


struct safe_allocation {
	size_t	size;
	char	data[1];
};

static char *error=NULL;

void set_error_va(const char *fmt, va_list va)
{

	if(error) {
	    free(error);
	    error=NULL;
	}

	if(!fmt) return;

	if (vasprintf(&error, fmt, va) < 0) {
		free(error);
		error = NULL;
	}
}

void set_error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	set_error_va(fmt, va);
	va_end(va);
}

const char *get_error(void)
{
	return error;
}

void *safe_alloc(size_t size)
{
	struct safe_allocation *alloc;

	if (!size)
		return NULL;

	alloc = malloc(size + offsetof(struct safe_allocation, data));
	if (!alloc)
		return NULL;

	alloc->size = size;

	return &alloc->data;
}

void safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = data - offsetof(struct safe_allocation, data);

	memset(data, 0, alloc->size);

	alloc->size = 0x55aa55aa;
	free(alloc);
}

void *safe_realloc(void *data, size_t size)
{
	void *new_data;

	new_data = safe_alloc(size);

	if (new_data && data) {
		struct safe_allocation *alloc;

		alloc = data - offsetof(struct safe_allocation, data);

		if (size > alloc->size)
			size = alloc->size;

		memcpy(new_data, data, size);
	}

	safe_free(data);
	return new_data;
}

char *safe_strdup(const char *s)
{
	char *s2 = safe_alloc(strlen(s) + 1);

	if (!s2)
		return NULL;

	return strcpy(s2, s);
}

/* Credits go to Michal's padlock patches for this alignment code */

static void *aligned_malloc(char **base, int size, int alignment) 
{
	char *ptr;

	ptr  = malloc(size + alignment);
	if(ptr == NULL) return NULL;

	*base = ptr;
	if(alignment > 1 && ((long)ptr & (alignment - 1))) {
		ptr += alignment - ((long)(ptr) & (alignment - 1));
	}
	return ptr;
}

static int sector_size(int fd) 
{
	int bsize;
	if (ioctl(fd,BLKSSZGET, &bsize) < 0)
		return -EINVAL;
	else
		return bsize;
}

int sector_size_for_device(const char *device)
{
	int fd = open(device, O_RDONLY);
	int r;
	if(fd < 0)
		return -EINVAL;
	r = sector_size(fd);
	close(fd);
	return r;
}

ssize_t write_blockwise(int fd, const void *orig_buf, size_t count) 
{
	char *padbuf; char *padbuf_base;
	char *buf = (char *)orig_buf;
	int r = 0;
	int hangover; int solid; int bsize;

	if ((bsize = sector_size(fd)) < 0)
		return bsize;

	hangover = count % bsize;
	solid = count - hangover;

	padbuf = aligned_malloc(&padbuf_base, bsize, bsize);
	if(padbuf == NULL) return -ENOMEM;

	while(solid) {
		memcpy(padbuf, buf, bsize);
		r = write(fd, padbuf, bsize);
		if(r < 0 || r != bsize) goto out;

		solid -= bsize;
		buf += bsize;
	}
	if(hangover) {
		r = read(fd,padbuf,bsize);
		if(r < 0 || r != bsize) goto out;

		lseek(fd,-bsize,SEEK_CUR);
		memcpy(padbuf,buf,hangover);

		r = write(fd,padbuf, bsize);
		if(r < 0 || r != bsize) goto out;
		buf += hangover;
	}
 out:
	free(padbuf_base);
	return (buf-(char *)orig_buf)?(buf-(char *)orig_buf):r;

}

ssize_t read_blockwise(int fd, void *orig_buf, size_t count) {
	char *padbuf; char *padbuf_base;
	char *buf = (char *)orig_buf;
	int r = 0;
	int step;
	int bsize;

	if ((bsize = sector_size(fd)) < 0)
		return bsize;

	padbuf = aligned_malloc(&padbuf_base, bsize, bsize);
	if(padbuf == NULL) return -ENOMEM;

	while(count) {
		r = read(fd,padbuf,bsize);
		if(r < 0 || r != bsize) {
			set_error("read failed in read_blockwise.\n");
			goto out;
		}
		step = count<bsize?count:bsize;
		memcpy(buf,padbuf,step);
		buf += step;
		count -= step;
	}
 out:
	free(padbuf_base); 
	return (buf-(char *)orig_buf)?(buf-(char *)orig_buf):r;
}

/* 
 * Combines llseek with blockwise write. write_blockwise can already deal with short writes
 * but we also need a function to deal with short writes at the start. But this information
 * is implicitly included in the read/write offset, which can not be set to non-aligned 
 * boundaries. Hence, we combine llseek with write.
 */

ssize_t write_lseek_blockwise(int fd, const char *buf, size_t count, off_t offset) {
	int bsize = sector_size(fd);
	const char *orig_buf = buf;
	char frontPadBuf[bsize];
	int frontHang = offset % bsize;
	int r;
	int innerCount = count < bsize ? count : bsize;

	if (bsize < 0)
		return bsize;

	lseek(fd, offset - frontHang, SEEK_SET);
	if(offset % bsize) {
		r = read(fd,frontPadBuf,bsize);
		if(r < 0) return -1;

		memcpy(frontPadBuf+frontHang, buf, innerCount);

		lseek(fd, offset - frontHang, SEEK_SET);
		r = write(fd,frontPadBuf,bsize);
		if(r < 0) return -1;

		buf += innerCount;
		count -= innerCount;
	}
	if(count <= 0) return buf - orig_buf;

	return write_blockwise(fd, buf, count) + innerCount;
}

/* Password reading helpers */

static int untimed_read(int fd, char *pass, size_t maxlen)
{
	ssize_t i;

	i = read(fd, pass, maxlen);
	if (i > 0) {
		pass[i-1] = '\0';
		i = 0;
	} else if (i == 0) { /* EOF */
		*pass = 0;
		i = -1;
	}
	return i;
}

static int timed_read(int fd, char *pass, size_t maxlen, long timeout)
{
	struct timeval t;
	fd_set fds;
	int failed = -1;

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	t.tv_sec = timeout;
	t.tv_usec = 0;

	if (select(fd+1, &fds, NULL, NULL, &t) > 0)
		failed = untimed_read(fd, pass, maxlen);
	else
		set_error("Operation timed out");
	return failed;
}

static int interactive_pass(const char *prompt, char *pass, size_t maxlen,
		long timeout)
{
	struct termios orig, tmp;
	int failed = -1;
	int infd = STDIN_FILENO, outfd;

	if (maxlen < 1)
		goto out_err;

	/* Read and write to /dev/tty if available */
	if ((infd = outfd = open("/dev/tty", O_RDWR)) == -1) {
		infd = STDIN_FILENO;
		outfd = STDERR_FILENO;
	}

	if (tcgetattr(infd, &orig)) {
		set_error("Unable to get terminal");
		goto out_err;
	}
	memcpy(&tmp, &orig, sizeof(tmp));
	tmp.c_lflag &= ~ECHO;

	if (write(outfd, prompt, strlen(prompt)) < 0)
		goto out_err;

	tcsetattr(infd, TCSAFLUSH, &tmp);
	if (timeout)
		failed = timed_read(infd, pass, maxlen, timeout);
	else
		failed = untimed_read(infd, pass, maxlen);
	tcsetattr(infd, TCSAFLUSH, &orig);

out_err:
	if (!failed)
		(void)write(outfd, "\n", 1);
	if (infd != STDIN_FILENO)
		close(infd);
	return failed;
}

/*
 * Password reading behaviour matrix of get_key
 * 
 *                    p   v   n   h
 * -----------------+---+---+---+---
 * interactive      | Y | Y | Y | Inf
 * from fd          | N | N | Y | Inf
 * from binary file | N | N | N | Inf or options->key_size
 *
 * Legend: p..prompt, v..can verify, n..newline-stop, h..read horizon
 *
 * Note: --key-file=- is interpreted as a read from a binary file (stdin)
 *
 * Returns true when more keys are available (that is when password
 * reading can be retried as for interactive terminals).
 */

int get_key(char *prompt, char **key, unsigned int *passLen, int key_size,
            const char *key_file, int passphrase_fd, int timeout, int how2verify)
{
	int fd;
	const int verify = how2verify & CRYPT_FLAG_VERIFY;
	const int verify_if_possible = how2verify & CRYPT_FLAG_VERIFY_IF_POSSIBLE;
	char *pass = NULL;
	int newline_stop;
	int read_horizon;

	if(key_file && !strcmp(key_file, "-")) {
		/* Allow binary reading from stdin */
		fd = passphrase_fd;
		newline_stop = 0;
		read_horizon = 0;
	} else if (key_file) {
		fd = open(key_file, O_RDONLY);
		if (fd < 0) {
			char buf[128];
			set_error("Error opening key file: %s",
				  strerror_r(errno, buf, 128));
			goto out_err;
		}
		newline_stop = 0;

		/* This can either be 0 (LUKS) or the actually number
		 * of key bytes (default or passed by -s) */
		read_horizon = key_size;
	} else {
		fd = passphrase_fd;
		newline_stop = 1;
		read_horizon = 0;   /* Infinite, if read from terminal or fd */
	}

	/* Interactive case */
	if(isatty(fd)) {
		int i;

		pass = safe_alloc(512);
		if (!pass || (i = interactive_pass(prompt, pass, 512, timeout))) {
			set_error("Error reading passphrase");
			goto out_err;
		}
		if (verify || verify_if_possible) {
			char pass_verify[512];
			i = interactive_pass("Verify passphrase: ", pass_verify, sizeof(pass_verify), timeout);
			if (i || strcmp(pass, pass_verify) != 0) {
				set_error("Passphrases do not match");
				goto out_err;
			}
			memset(pass_verify, 0, sizeof(pass_verify));
		}
		*passLen = strlen(pass);
		*key = pass;
	} else {
		/* 
		 * This is either a fd-input or a file, in neither case we can verify the input,
		 * however we don't stop on new lines if it's a binary file.
		 */
		int buflen, i;

		if(verify) {
			set_error("Can't do passphrase verification on non-tty inputs");
			goto out_err;
		}
		/* The following for control loop does an exhausting
		 * read on the key material file, if requested with
		 * key_size == 0, as it's done by LUKS. However, we
		 * should warn the user, if it's a non-regular file,
		 * such as /dev/random, because in this case, the loop
		 * will read forever.
		 */ 
		if(key_file && strcmp(key_file, "-") && read_horizon == 0) {
			struct stat st;
			if(stat(key_file, &st) < 0) {
		 		set_error("Can't stat key file");
				goto out_err;
			}
			if(!S_ISREG(st.st_mode)) {
				//		 		set_error("Can't do exhausting read on non regular files");
				// goto out_err;
				fprintf(stderr,"Warning: exhausting read requested, but key file is not a regular file, function might never return.\n");
			}
		}
		buflen = 0;
		for(i = 0; read_horizon == 0 || i < read_horizon; i++) {
			if(i >= buflen - 1) {
				buflen += 128;
				pass = safe_realloc(pass, buflen);
				if (!pass) {
					set_error("Not enough memory while "
					          "reading passphrase");
					goto out_err;
				}
			}
			if(read(fd, pass + i, 1) != 1 || (newline_stop && pass[i] == '\n'))
				break;
		}
		if(key_file)
			close(fd);
		pass[i] = 0;
		*key = pass;
		*passLen = i;
	}

	return isatty(fd); /* Return true, when password reading can be tried on interactive fds */

out_err:
	if(pass)
		safe_free(pass);
	*key = NULL;
	*passLen = 0;
	return 0;
}

