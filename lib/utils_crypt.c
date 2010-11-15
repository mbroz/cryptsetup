#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "libcryptsetup.h"
#include "nls.h"
#include "utils_crypt.h"

struct safe_allocation {
	size_t	size;
	char	data[0];
};

int crypt_parse_name_and_mode(const char *s, char *cipher, char *cipher_mode)
{
	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
		   cipher, cipher_mode) == 2) {
		if (!strcmp(cipher_mode, "plain"))
			strncpy(cipher_mode, "cbc-plain", 10);
		return 0;
	}

	if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
		strncpy(cipher_mode, "cbc-plain", 10);
		return 0;
	}

	return -EINVAL;
}

/* safe allocations */
void *crypt_safe_alloc(size_t size)
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

void crypt_safe_free(void *data)
{
	struct safe_allocation *alloc;

	if (!data)
		return;

	alloc = data - offsetof(struct safe_allocation, data);

	memset(data, 0, alloc->size);

	alloc->size = 0x55aa55aa;
	free(alloc);
}

void *crypt_safe_realloc(void *data, size_t size)
{
	void *new_data;

	new_data = crypt_safe_alloc(size);

	if (new_data && data) {
		struct safe_allocation *alloc;

		alloc = data - offsetof(struct safe_allocation, data);

		if (size > alloc->size)
			size = alloc->size;

		memcpy(new_data, data, size);
	}

	crypt_safe_free(data);
	return new_data;
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

	if (tcgetattr(infd, &orig))
		goto out_err;

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
	if (!failed && write(outfd, "\n", 1)) {};

	if (infd != STDIN_FILENO)
		close(infd);
	return failed;
}

/*
 * Password reading behaviour matrix of get_key
 * FIXME: rewrite this from scratch.
 *                    p   v   n   h
 * -----------------+---+---+---+---
 * interactive      | Y | Y | Y | Inf
 * from fd          | N | N | Y | Inf
 * from binary file | N | N | N | Inf or options->key_size
 *
 * Legend: p..prompt, v..can verify, n..newline-stop, h..read horizon
 *
 * Note: --key-file=- is interpreted as a read from a binary file (stdin)
 */

int crypt_get_key(char *prompt, char **key, unsigned int *passLen, int key_size,
		  const char *key_file, int timeout, int verify,
		  struct crypt_device *cd)
{
	int fd = -1;
	char *pass = NULL;
	int read_horizon;
	int regular_file = 0;
	int read_stdin;
	int r;
	struct stat st;

	/* Passphrase read from stdin? */
	read_stdin = (!key_file || !strcmp(key_file, "-")) ? 1 : 0;

	/* read_horizon applies only for real keyfile, not stdin or terminal */
	read_horizon = (key_file && !read_stdin) ? key_size : 0 /* until EOF */;

	/* Setup file descriptior */
	fd = read_stdin ? STDIN_FILENO : open(key_file, O_RDONLY);
	if (fd < 0) {
		crypt_log(cd, CRYPT_LOG_ERROR,
			  _("Failed to open key file.\n"));
		goto out_err;
	}

	/* Interactive case */
	if(isatty(fd)) {
		int i;

		pass = crypt_safe_alloc(MAX_TTY_PASSWORD_LEN);
		if (!pass || interactive_pass(prompt, pass, MAX_TTY_PASSWORD_LEN, timeout)) {
			crypt_log(cd, CRYPT_LOG_ERROR,
				  _("Error reading passphrase from terminal.\n"));
			goto out_err;
		}
		if (verify) {
			char pass_verify[MAX_TTY_PASSWORD_LEN];
			i = interactive_pass(_("Verify passphrase: "), pass_verify, sizeof(pass_verify), timeout);
			if (i || strcmp(pass, pass_verify) != 0) {
				crypt_log(cd, CRYPT_LOG_ERROR,
				 _("Passphrases do not match.\n"));
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

		/* The following for control loop does an exhausting
		 * read on the key material file, if requested with
		 * key_size == 0, as it's done by LUKS. However, we
		 * should warn the user, if it's a non-regular file,
		 * such as /dev/random, because in this case, the loop
		 * will read forever.
		 */
		if(!read_stdin && read_horizon == 0) {
			if(stat(key_file, &st) < 0) {
				crypt_log(cd, CRYPT_LOG_ERROR,
					_("Failed to stat key file.\n"));
				goto out_err;
			}
			if(!S_ISREG(st.st_mode))
				crypt_log(cd, CRYPT_LOG_NORMAL,
					  _("Warning: exhausting read requested, but key file"
					    " is not a regular file, function might never return.\n"));
			else
				regular_file = 1;
		}
		buflen = 0;
		for(i = 0; read_horizon == 0 || i < read_horizon; i++) {
			if(i >= buflen - 1) {
				buflen += 128;
				pass = crypt_safe_realloc(pass, buflen);
				if (!pass) {
					crypt_log(cd, CRYPT_LOG_ERROR,
						  _("Out of memory while reading passphrase.\n"));
					goto out_err;
				}
			}

			r = read(fd, pass + i, 1);
			if (r < 0) {
				crypt_log(cd, CRYPT_LOG_ERROR,
					  _("Error reading passphrase.\n"));
				goto out_err;
			}

			/* Stop on newline only if not requested read from keyfile */
			if(r == 0 || (!key_file && pass[i] == '\n'))
				break;
		}
		/* Fail if piped input dies reading nothing */
		if(!i && !regular_file)
			goto out_err;
		pass[i] = 0;
		*key = pass;
		*passLen = i;
	}
	if(fd != STDIN_FILENO)
		close(fd);
	return 0;

out_err:
	if(fd >= 0 && fd != STDIN_FILENO)
		close(fd);
	if(pass)
		crypt_safe_free(pass);
	*key = NULL;
	*passLen = 0;
	return -EINVAL;
}
