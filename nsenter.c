/*
 * nsenter(1) - command-line interface for setns(2)
 *
 * Copyright (C) 2012-2013 Eric Biederman <ebiederm@xmission.com>
 * Copyright (C) 2015 Jörg Thalheim <joerg@higgsboson.tk>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _XOPEN_SOURCE 700
#define PACKAGE_STRING "nsenter"
#define _GNU_SOURCE 1

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <termios.h>
#include <unistd.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sched.h>
#include <term.h>
#include <grp.h>
#include <linux/sched.h>
#include <stdio_ext.h>

#include "c.h"

unsigned long strtoul_or_err(const char *str, const char *errmesg)
{
	unsigned long num;
	char *end = NULL;

	if (str == NULL || *str == '\0')
		goto err;
	errno = 0;
	num = strtoul(str, &end, 10);

	if (errno || str == end || (end && *end))
		goto err;

	return num;
err:
	if (errno)
		err(EXIT_FAILURE, "%s: '%s'", errmesg, str);

	errx(EXIT_FAILURE, "%s: '%s'", errmesg, str);
}

#define DEFAULT_SHELL "/bin/sh"

void exec_shell(void)
{
	const char *shell = getenv("SHELL"), *shell_basename;
	char *arg0;
	if (!shell)
		shell = DEFAULT_SHELL;

	shell_basename = basename(shell);
	arg0 = malloc(strlen(shell_basename) + 2);
	if (!arg0)
		err(EXIT_FAILURE, "failed to allocate memory");
	arg0[0] = '-';
	strcpy(arg0 + 1, shell_basename);

	execl(shell, arg0, NULL);
	err(EXIT_FAILURE, "failed to execute %s", shell);
}

static struct namespace_file {
	int nstype;
	const char *name;
	int fd;
} namespace_files[] = {
	/* Careful the order is significant in this array.
	 *
	 * The user namespace comes first, so that it is entered
	 * first.  This gives an unprivileged user the potential to
	 * enter the other namespaces.
	 */
	{ .nstype = CLONE_NEWUSER, .name = "ns/user", .fd = -1 },
	{ .nstype = CLONE_NEWIPC,  .name = "ns/ipc",  .fd = -1 },
	{ .nstype = CLONE_NEWUTS,  .name = "ns/uts",  .fd = -1 },
	{ .nstype = CLONE_NEWNET,  .name = "ns/net",  .fd = -1 },
	{ .nstype = CLONE_NEWPID,  .name = "ns/pid",  .fd = -1 },
	{ .nstype = CLONE_NEWNS,   .name = "ns/mnt",  .fd = -1 },
	{ .nstype = 0, .name = NULL, .fd = -1 }
};

static void usage(int status)
{
	FILE *out = status == EXIT_SUCCESS ? stdout : stderr;

	fputs(USAGE_HEADER, out);
	fprintf(out, " %s [options] <program> [<argument>...]\n",
		program_invocation_short_name);

	fputs(USAGE_SEPARATOR, out);
	fputs("Run a program with namespaces of other processes.\n", out);

	fputs(USAGE_OPTIONS, out);
	fputs(" -t, --target <pid>     target process to get namespaces from\n", out);
	fputs(" -m, --mount[=<file>]   enter mount namespace\n", out);
	fputs(" -u, --uts[=<file>]     enter UTS namespace (hostname etc)\n", out);
	fputs(" -i, --ipc[=<file>]     enter System V IPC namespace\n", out);
	fputs(" -n, --net[=<file>]     enter network namespace\n", out);
	fputs(" -p, --pid[=<file>]     enter pid namespace\n", out);
	fputs(" -U, --user[=<file>]    enter user namespace\n", out);
	fputs(" -S, --setuid <uid>     set uid in entered namespace\n", out);
	fputs(" -G, --setgid <gid>     set gid in entered namespace\n", out);
	fputs("     --preserve-credentials do not touch uids or gids\n", out);
	fputs(" -P, --pty              allocate a pseudo-TTY (this implies forking)\n", out);
	fputs(" -r, --root[=<dir>]     set the root directory\n", out);
	fputs(" -w, --wd[=<dir>]       set the working directory\n", out);
	fputs(" -F, --no-fork          do not fork before exec'ing <program>\n", out);

	fputs(USAGE_SEPARATOR, out);
	fputs(USAGE_HELP, out);
	fputs(USAGE_VERSION, out);
	fprintf(out, USAGE_MAN_TAIL("nsenter(1)"));

	exit(status);
}

static pid_t namespace_target_pid = 0;
static int root_fd = -1;
static int wd_fd = -1;
static struct termios stdin_termios, stdout_termios;
static int tty_master_fd;

static void open_target_fd(int *fd, const char *type, const char *path)
{
	char pathbuf[PATH_MAX];

	if (!path && namespace_target_pid) {
		snprintf(pathbuf, sizeof(pathbuf), "/proc/%u/%s",
			 namespace_target_pid, type);
		path = pathbuf;
	}
	if (!path)
		errx(EXIT_FAILURE,
		     "neither filename nor target pid supplied for %s",
		     type);

	if (*fd >= 0)
		close(*fd);

	*fd = open(path, O_RDONLY);
	if (*fd < 0)
		err(EXIT_FAILURE, "cannot open %s", path);
}

static void open_namespace_fd(int nstype, const char *path)
{
	struct namespace_file *nsfile;

	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nstype != nsfile->nstype)
			continue;

		open_target_fd(&nsfile->fd, nsfile->name, path);
		return;
	}
	/* This should never happen */
	assert(nsfile->nstype);
}

static void resize_on_signal(int signo __attribute__((__unused__)))
{
	struct winsize winsize;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &winsize) != -1)
		ioctl(tty_master_fd, TIOCSWINSZ, &winsize);
}

static void restore_stdin(void)
{
	if (tcsetattr(STDIN_FILENO, TCSANOW, &stdin_termios) == -1)
		errx(EXIT_FAILURE,
				"failed to restore stdin terminal attributes");
}

static void restore_stdout(void)
{
	if (tcsetattr(STDOUT_FILENO, TCSANOW, &stdout_termios) == -1)
		errx(EXIT_FAILURE,
				"failed to restore stdout terminal attributes");
}


static int set_tty_raw(int fd, struct termios *origin_attr)
{
	struct termios attr[1];

	if (tcgetattr(fd, attr) == -1)
		return -1;

	memcpy(origin_attr, attr, sizeof(struct termios));

	cfmakeraw(attr);

	return tcsetattr(fd, TCSANOW, attr);
}

static void shovel_tty(int master_fd, int in_fd) {
	fd_set read_fds[1];
	int max_fd;
	char buf[BUFSIZ];
	ssize_t bytes;
	int n;
	while (master_fd != -1) {

		FD_ZERO(read_fds);

		if (in_fd != -1)
			FD_SET(in_fd, read_fds);

		if (master_fd != -1)
			FD_SET(master_fd, read_fds);

		max_fd = (master_fd > in_fd) ? master_fd : in_fd;

		if ((n = select(max_fd + 1, read_fds, NULL, NULL, NULL)) == -1 && errno != EINTR)
			break;

		if (n == -1 && errno == EINTR)
			continue;

		if (in_fd != -1 && FD_ISSET(in_fd, read_fds)) {
			if ((bytes = read(in_fd, buf, BUFSIZ)) > 0) {
				if (master_fd != -1 && write(master_fd, buf, bytes) == -1)
					break;
			} else if (n == -1 && errno == EINTR) {
				continue;
			} else {
				in_fd = -1;
				continue;
			}
		}

		if (master_fd != -1 && FD_ISSET(master_fd, read_fds)) {
			if ((bytes = read(master_fd, buf, BUFSIZ)) > 0) {
				if (write(STDOUT_FILENO, buf, bytes) == -1)
					break;
			} else if (n == -1 && errno == EINTR) {
				continue;
			} else {
				close(master_fd);
				master_fd = -1;
				continue;
			}
		}
	}
}

static void setup_pty_parent(int master_fd)
{
	struct sigaction sa;
	struct winsize ws;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sa.sa_handler = resize_on_signal;
	sigaction(SIGWINCH, &sa, NULL);

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0)
		(void) ioctl(master_fd, TIOCSWINSZ, &ws);

	if (set_tty_raw(STDIN_FILENO, &stdin_termios) != -1) {
		atexit((void (*)(void))restore_stdin);
	}

	if (set_tty_raw(STDOUT_FILENO, &stdout_termios) != -1) {
		atexit((void (*)(void))restore_stdout);
	}
}

static int setup_pty_child(int master_fd)
{
	pid_t pid;
	int slave_fd;

	char* slave_name = ptsname(master_fd);
	if (slave_name == NULL)
		return -errno;

	slave_fd = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
	if (slave_fd < -1)
		return -errno;

	pid = setsid();
	if (pid < 0 && errno != EPERM)
		return -errno;

	if (ioctl(slave_fd, TIOCSCTTY, 0) < 0)
		return -errno;

	if (dup2(slave_fd, STDIN_FILENO) != STDIN_FILENO ||
			dup2(slave_fd, STDOUT_FILENO) != STDOUT_FILENO ||
			dup2(slave_fd, STDERR_FILENO) != STDERR_FILENO)
		return -errno;

	/*only close, if slave_fd is not std-fd*/
	if (slave_fd > 2)
		close(slave_fd);

	return 0;
}

static int new_pty(void)
{
	int fd = posix_openpt(O_RDWR | O_NOCTTY);

	if (fd < 0)
		return -errno;

	if (grantpt(fd) < 0)
		return -errno;

	if (unlockpt(fd) < 0)
		return -errno;

	return fd;
}

static void continue_as_child(bool open_pty)
{
	pid_t child;
	int status;
	pid_t ret;
	int master_fd = -1;

	if (open_pty) {
		master_fd = new_pty();
		if (master_fd < 0)
			err(EXIT_FAILURE, "open pseudo tty failed");
	}

	child = fork();

	if (child < 0)
		err(EXIT_FAILURE, "fork failed");

	/* Only the child returns */
	if (child == 0) {
		if (open_pty && setup_pty_child(master_fd) < 0)
			err(EXIT_FAILURE, "failed to setup slave of pseudo tty");
		close(master_fd);
		return;
	}

	if (open_pty) {
		tty_master_fd = master_fd;
		setup_pty_parent(master_fd);
	}

	for (;;) {
		if (open_pty)
			shovel_tty(master_fd, STDIN_FILENO);
		ret = waitpid(child, &status, WUNTRACED);
		if ((ret == child) && (WIFSTOPPED(status))) {
			/* The child suspended so suspend us as well */
			kill(getpid(), SIGSTOP);
			kill(child, SIGCONT);
		} else {
			break;
		}
	}
	/* Return the child's exit code if possible */
	if (WIFEXITED(status)) {
		exit(WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		kill(getpid(), WTERMSIG(status));
	}
	exit(EXIT_FAILURE);
}

static inline int
close_stream(FILE * stream)
{
	const int some_pending = (__fpending(stream) != 0);
	const int prev_fail = (ferror(stream) != 0);
	const int fclose_fail = (fclose(stream) != 0);

	if (prev_fail || (fclose_fail && (some_pending || errno != EBADF))) {
		if (!fclose_fail && !(errno == EPIPE))
			errno = 0;
		return EOF;
	}
	return 0;
}

/* Meant to be used atexit(close_stdout); */
static inline void
close_stdout(void)
{
	if (close_stream(stdout) != 0 && !(errno == EPIPE)) {
		if (errno)
			warn("write error");
		else
			warnx("write error");
		_exit(EXIT_FAILURE);
	}

	if (close_stream(stderr) != 0)
		_exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	enum {
		OPT_PRESERVE_CRED = CHAR_MAX + 1
	};
	static const struct option longopts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "pty", no_argument, NULL, 'P' },
		{ "version", no_argument, NULL, 'V'},
		{ "target", required_argument, NULL, 't' },
		{ "mount", optional_argument, NULL, 'm' },
		{ "uts", optional_argument, NULL, 'u' },
		{ "ipc", optional_argument, NULL, 'i' },
		{ "net", optional_argument, NULL, 'n' },
		{ "pid", optional_argument, NULL, 'p' },
		{ "user", optional_argument, NULL, 'U' },
		{ "setuid", required_argument, NULL, 'S' },
		{ "setgid", required_argument, NULL, 'G' },
		{ "root", optional_argument, NULL, 'r' },
		{ "wd", optional_argument, NULL, 'w' },
		{ "no-fork", no_argument, NULL, 'F' },
		{ "preserve-credentials", no_argument, NULL, OPT_PRESERVE_CRED },
		{ NULL, 0, NULL, 0 }
	};

	struct namespace_file *nsfile;
	int c, namespaces = 0, setgroups_nerrs = 0, preserve_cred = 0;
	bool do_rd = false, do_wd = false, force_uid = false, force_gid = false, open_pty = false;
	int do_fork = -1; /* unknown yet */
	uid_t uid = 0;
	gid_t gid = 0;

	atexit(close_stdout);

	while ((c =
		getopt_long(argc, argv, "+hPVt:m::u::i::n::p::U::S:G:r::w::F",
			    longopts, NULL)) != -1) {
		switch (c) {
		case 'h':
			usage(EXIT_SUCCESS);
		case 'V':
			printf(UTIL_LINUX_VERSION);
			return EXIT_SUCCESS;
		case 't':
			namespace_target_pid =
			    strtoul_or_err(optarg, "failed to parse pid");
			break;
		case 'm':
			if (optarg)
				open_namespace_fd(CLONE_NEWNS, optarg);
			else
				namespaces |= CLONE_NEWNS;
			break;
		case 'u':
			if (optarg)
				open_namespace_fd(CLONE_NEWUTS, optarg);
			else
				namespaces |= CLONE_NEWUTS;
			break;
		case 'i':
			if (optarg)
				open_namespace_fd(CLONE_NEWIPC, optarg);
			else
				namespaces |= CLONE_NEWIPC;
			break;
		case 'n':
			if (optarg)
				open_namespace_fd(CLONE_NEWNET, optarg);
			else
				namespaces |= CLONE_NEWNET;
			break;
		case 'p':
			if (optarg)
				open_namespace_fd(CLONE_NEWPID, optarg);
			else
				namespaces |= CLONE_NEWPID;
			break;
		case 'P':
			open_pty = true;
			break;
		case 'U':
			if (optarg)
				open_namespace_fd(CLONE_NEWUSER, optarg);
			else
				namespaces |= CLONE_NEWUSER;
			break;
		case 'S':
			uid = strtoul_or_err(optarg, "failed to parse uid");
			force_uid = true;
			break;
		case 'G':
			gid = strtoul_or_err(optarg, "failed to parse gid");
			force_gid = true;
			break;
		case 'F':
			do_fork = 0;
			break;
		case 'r':
			if (optarg)
				open_target_fd(&root_fd, "root", optarg);
			else
				do_rd = true;
			break;
		case 'w':
			if (optarg)
				open_target_fd(&wd_fd, "cwd", optarg);
			else
				do_wd = true;
			break;
		case OPT_PRESERVE_CRED:
			preserve_cred = 1;
			break;
		default:
			usage(EXIT_FAILURE);
		}
	}

	/*
	 * Open remaining namespace and directory descriptors.
	 */
	for (nsfile = namespace_files; nsfile->nstype; nsfile++)
		if (nsfile->nstype & namespaces)
			open_namespace_fd(nsfile->nstype, NULL);
	if (do_rd)
		open_target_fd(&root_fd, "root", NULL);
	if (do_wd)
		open_target_fd(&wd_fd, "cwd", NULL);

	/*
	 * Update namespaces variable to contain all requested namespaces
	 */
	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nsfile->fd < 0)
			continue;
		namespaces |= nsfile->nstype;
	}

	/* for user namespaces we always set UID and GID (default is 0)
	 * and clear root's groups if --preserve-credentials is no specified */
	if ((namespaces & CLONE_NEWUSER) && !preserve_cred) {
		force_uid = true, force_gid = true;

		/* We call setgroups() before and after we enter user namespace,
		 * let's complain only if both fail */
		if (setgroups(0, NULL) != 0)
			setgroups_nerrs++;
	}

	/*
	 * Now that we know which namespaces we want to enter, enter them.
	 */
	for (nsfile = namespace_files; nsfile->nstype; nsfile++) {
		if (nsfile->fd < 0)
			continue;
		if (nsfile->nstype == CLONE_NEWPID && do_fork == -1)
			do_fork = 1;
		if (setns(nsfile->fd, nsfile->nstype))
			err(EXIT_FAILURE,
			    "reassociate to namespace '%s' failed",
			    nsfile->name);
		close(nsfile->fd);
		nsfile->fd = -1;
	}

	/* Remember the current working directory if I'm not changing it */
	if (root_fd >= 0 && wd_fd < 0) {
		wd_fd = open(".", O_RDONLY);
		if (wd_fd < 0)
			err(EXIT_FAILURE,
			    "cannot open current working directory");
	}

	/* Change the root directory */
	if (root_fd >= 0) {
		if (fchdir(root_fd) < 0)
			err(EXIT_FAILURE,
			    "change directory by root file descriptor failed");

		if (chroot(".") < 0)
			err(EXIT_FAILURE, "chroot failed");

		close(root_fd);
		root_fd = -1;
	}

	/* Change the working directory */
	if (wd_fd >= 0) {
		if (fchdir(wd_fd) < 0)
			err(EXIT_FAILURE,
			    "change directory by working directory file descriptor failed");

		close(wd_fd);
		wd_fd = -1;
	}

	if (do_fork == 1 || open_pty)
		continue_as_child(open_pty);

	if (force_uid || force_gid) {
		if (force_gid && setgroups(0, NULL) != 0 && setgroups_nerrs)	/* drop supplementary groups */
			err(EXIT_FAILURE, "setgroups failed");
		if (force_gid && setgid(gid) < 0)		/* change GID */
			err(EXIT_FAILURE, "setgid failed");
		if (force_uid && setuid(uid) < 0)		/* change UID */
			err(EXIT_FAILURE, "setuid failed");
	}

	if (optind < argc) {
		execvp(argv[optind], argv + optind);
		err(EXIT_FAILURE, "failed to execute %s", argv[optind]);
	}
	exec_shell();
}
