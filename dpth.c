#define FUSE_USE_VERSION 30
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <fuse.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DPTH_COUNTOF(x) (sizeof((x))/sizeof((x)[0]))

static const struct fuse_operations fuseops = {
};

int main(int argc, char *argv[]) {
	int status;
	pid_t pid;
	struct fuse_chan *fuse_channel;
	struct fuse *fuse_ctx;
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
		const char *fuse_argv[] = {
			"",
			"-f"
		};

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
			goto exit_dir;
		}

		fuse_ctx = fuse_new(
			fuse_channel,
			&fuse_args,
			&fuseops,
			sizeof(fuseops),
			NULL
		);

		if (fuse_ctx == NULL) {
			/* Same here; no error info. */
			goto exit_fuse_channel;
		}
	}

	switch ((pid = fork())) {
		case -1:
			perror("dpth: fork()");
			goto exit_fuse;
		case 0:
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

			if (waitpid(pid, &child_status, 0) == -1) {
				perror("dpth: waitpid()");

				if (kill(pid, SIGKILL) == -1) {
					perror("dpth: kill()");
				}

				goto exit_fuse;
			}

			status = WEXITSTATUS(child_status);

			break;
		}
	}

exit_fuse:
	assert(fuse_ctx != NULL);
	fuse_destroy(fuse_ctx);
exit_fuse_channel:
	assert(fuse_channel != NULL);
	fuse_unmount(tmpdir_path, fuse_channel);
exit_dir:
	if (rmdir(tmpdir_path) == -1) {
		status = 1;
		perror("dpth: rmdir()");
	}
exit:
	return status;
}
