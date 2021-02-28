#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <fuse.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#include <assert.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#define DPTH_COUNTOF(x) (sizeof((x))/sizeof((x)[0]))

static pid_t child_pid = 0;
static jmp_buf jump_env;

static int const signals_to_ignore[] = {
#ifdef SIGHUP
	SIGHUP,
#endif
#ifdef SIGQUIT
	SIGQUIT,
#endif

	SIGINT,
	SIGTERM
};

static char * dpth_strdup(const char *original) {
	size_t len = strlen(original) + 1;
	char *buf = malloc(len);
	return buf == NULL
		? NULL
		: memcpy(buf, original, len);
}

static void handle_SIGCHLD(int signum) {
	(void) signum;
	assert(signum == SIGCHLD);
	longjmp(jump_env, 1);
}

static int setsig_or_perror(int sig, int restart, void (*handler)(int)) {
	struct sigaction action;
	action.sa_flags = SA_NOCLDSTOP | (restart ? SA_RESTART : 0);
	sigfillset(&action.sa_mask);
	action.sa_restorer = 0;
	action.sa_handler = handler;

	if (sigaction(sig, &action, NULL) == -1) {
		perror("dpth: sigaction()");
		return 1;
	}

	return 0;
}

static char * getenv_child(const char *name) {

}

/* return value MUST be free()'d if not NULL! */
static char * get_PATH(void) {
	if (child_pid == 0) {
		/*
			we haven't set up a child, but for some reason (perhaps
			another program) we're being asked to grab its PATH
			variable.

			simply ignore the request.
		*/
		return NULL;
	}

	char *pathenv = getenv_child("PATH");

	if (pathenv == NULL) {
		errno = 0;
		size_t len = confstr(_CS_PATH, NULL, 0);

		if (len == 0) {
			if (errno == EINVAL) {
				/* TODO use diagnostic instead of this */
				fputs("@@@ DPTH @@@: WARNING: confstr(_CS_PATH) indicated it didn't understand the variable\n", stderr);
			}
		} else {
			pathenv = malloc(len);

			if (pathenv == NULL) {
				/* TODO use defines for the diagnostic prefix, and use them in the diagnostic function as well as here to keep things consistent */
				/* TODO alternatively, just use strerror() and pass to diagnostic */
				perror("@@@ DPTH @@@: WARNING: malloc()\n");
			} else {

				/* guaranteed to succeed */
#			ifndef NDEBUG
				size_t check_return =
#			endif
				confstr(_CS_PATH, pathenv, len);
#			ifndef NDEBUG
				assert(check_return == len);
#			endif
			}
		}
	} else {
		pathenv = dpth_strdup(pathenv);

		if (pathenv == NULL) {
			/* TODO use defines for the diagnostic prefix, and use them in the diagnostic function as well as here to keep things consistent */
			/* TODO alternatively, just use strerror() and pass to diagnostic */
			perror("@@@ DPTH @@@: WARNING: strdup() (via malloc())\n");
		}
	}

	return pathenv;
}

/* return value MUST be free()'d if not NULL! */
static char * try_stat_path(
	const char *base,
	size_t base_extent,
	const char *partial,
	size_t partial_extent,
	struct stat *statbuf
) {
	if (partial_extent == 0) {
		/* TODO maybe a diagnostic? */
		return NULL;
	}

	int needs_slash = (*partial != '/');

	/* construct the final path */
	char *buf = malloc(base_extent + needs_slash + partial_extent + 1);
	                 /*                  '/'                       NUL */

	memcpy(buf, base, base_extent);
	memcpy(buf + base_extent + needs_slash, partial, partial_extent);
	if (needs_slash) buf[base_extent] = '/';
	buf[base_extent + partial_extent + needs_slash] = 0;

	fprintf(stderr, "TRY STAT: %s\n", buf);
	if (stat(buf, statbuf) == -1) {
		free(buf);
		buf = NULL;
	}

	return buf;
}

/* return value MUST be free()'d if not NULL! */
static char * resolve_path(const char *partial, struct stat *statbuf, int diagnostic) {
	size_t partial_length;
	size_t PATH_length;
	char *PATH          = NULL;
	char *resolved_path = NULL;
	char *base_buffer   = NULL;

	PATH = get_PATH();
	if (PATH == NULL || (PATH_length = strlen(PATH)) == 0) {
		/*
			means an error; return NULL unconditionally,
			without error, since that function has already
			printed an error if it returned NULL.
		*/
		goto exit;
	}

	base_buffer = malloc(strlen(PATH));
	if (base_buffer == NULL) {
		/* TODO print diagnostic instead of this printf */
		perror("@@@ DPTH @@@: WARNING: malloc()\n");
		goto exit;
	}

	partial_length = strlen(partial);
	if (partial_length) {

	}

	if (diagnostic) /* TODO print diagnostic */ (void)0;

	for (size_t i = 0; i < PATH_length; i++) {

	}

	if (diagnostic) /* TODO print diagnostic */ (void)0;

exit:
	free(base_buffer);
	free(PATH);
	return resolved_path;
}

static int do_getattr(const char *path, struct stat *statbuf) {
	char *resolved = resolve_path(path, statbuf, 1);

	if (resolved == NULL) {
		/* TODO print diagnostic instead of this hacked-on fprintf statement */
		fprintf(stderr, "@@@ DPTH @@@: getattr(): %s: ENOENT\n", path);
		return -ENOENT;
	} else {
		/* TODO print diagnostic instead of this hacked-on fprintf statement */
		fprintf(stderr, "@@@ DPTH @@@: getattr(): %s: RESOLVED TO %s\n", path, resolved);
		free(resolved);
		return 0;
	}
}

static const struct fuse_operations fuseops = {
	.getattr = &do_getattr
};

int main(int argc, char *argv[]) {
	int status;
	pid_t pid;
	struct fuse_chan *fuse_channel = NULL;
	struct fuse *fuse_ctx = NULL;
	char tmpdir_path[] = "/tmp/dpth-XXXXXX";

	status = 1;

	if (argc <= 1 || strcmp("--help", argv[1]) == 0) {
		status = 2;
		fprintf(
			stderr,
			"Usage: %s [--help] <COMMAND> [ARGS]...\n"
			"Execute a COMMAND and log its $PATH lookups.\n"
			"Example: %s make all\n"
			"Arguments are passed as-is to exec().\n"
			"Path lookup diagnostics are printed to stderr.\n"
			"Written by Josh Junon (github.com/qix-/dpth)\n"
			"MIT License, (c) 2021\n",
			argv[0], argv[0]
		);
		goto exit;
	}

	if (mkdtemp(tmpdir_path) == NULL) {
		perror("dpth: mkdtemp()");
		goto exit;
	}

	{
		static char * const fuse_argv[] = { "" };

		struct fuse_args fuse_args = {
			.allocated = 0,
			.argc = DPTH_COUNTOF(fuse_argv),
			.argv = (char **)fuse_argv
		};

		fuse_channel = fuse_mount(
			tmpdir_path,
			&fuse_args
		);

		if (fuse_channel == NULL) {
			/*
				The fuse developers, with their infinite wisdom, do not
				give you programmatic error code access. Things are just
				blindly dumped to stderr.

				Sorry for any headache this causes. Nothing I can do about
				it without redesigning FUSE's frontend library.
			*/
			goto exit_fuse;
		}

		fuse_ctx = fuse_new(
			fuse_channel,
			&fuse_args,
			&fuseops,
			sizeof(fuseops),
			NULL
		);

		if (fuse_ctx == NULL) {
			/* Same here; no error info aside from what's printed to stderr. */
			goto exit_fuse;
		}
	}

	/*
		Set up child signal; this gets destroyed during our exec*() call below anyway,
		which is good because doing it inside the default case (parent process
		branch) below would cause a race condition.
	*/
	if (setsig_or_perror(SIGCHLD, 0, &handle_SIGCHLD)) goto exit_fuse;
	for (size_t i = 0; i < DPTH_COUNTOF(signals_to_ignore); i++) {
		if (
			setsig_or_perror(signals_to_ignore[i], 1, SIG_IGN)
		) {
			goto exit_fuse;
		}
	}

	switch ((pid = fork())) {
		case -1:
			perror("dpth: fork()");
			goto exit_fuse;
		case 0:
			for (size_t i = 0; i < DPTH_COUNTOF(signals_to_ignore); i++) {
				if (
					signal(signals_to_ignore[i], SIG_DFL) == SIG_ERR
				) {
					perror("dpth: signal()");
					return -3;
				}
			}

			if (setenv("PATH", tmpdir_path, 1) == -1) {
				perror("dpth: setenv()");
				return -2;
			}

			execvp(argv[1], argv + 1);

			perror("dpth: execvp()");
			return -1;
		default: {
			/* parent process */
			int child_status = 0;

			switch (setjmp(jump_env)) {
			case 1:
				/* child died */
				if (waitpid(pid, &child_status, 0) == -1) {
					perror("dpth: waitpid()");
					/* fall-through to case 2 (kill child process and exit) */
				} else {
					status = WEXITSTATUS(child_status);
					break;
				}

				/* intentional fallthrough */
			case 2:
				if (kill(pid, SIGKILL) == -1) {
					perror("dpth: kill()");
				}

				status = -4;

				goto exit_fuse;
			case 0:
				fuse_loop(fuse_ctx);
				/* should never return, and thus never hit here */
				assert(!"FUSE loop returned prematurely");
				longjmp(jump_env, 2);
			}

			break;
		}
	}

exit_fuse:
	if (fuse_channel) fuse_unmount(tmpdir_path, fuse_channel);
	if (fuse_ctx) fuse_destroy(fuse_ctx);

	if (rmdir(tmpdir_path) == -1) {
		status = 1;
		perror("dpth: rmdir()");
	}
exit:
	return status;
}
