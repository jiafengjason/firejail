/*
 * Copyright (C) 2014-2020 Firejail Authors
 *
 * This file is part of firejail project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "firejail.h"
#include "../include/pid.h"
#include "../include/firejail_user.h"
#include "../include/syscall.h"
#include "../include/seccomp.h"
#define _GNU_SOURCE
#include <sys/utsname.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pwd.h>
#include <errno.h>
//#include <limits.h>
#include <sys/file.h>
#include <sys/prctl.h>
#include <signal.h>
#include <time.h>
#include <net/if.h>
#include <sys/utsname.h>

#include <fcntl.h>
#ifndef O_PATH
#define O_PATH 010000000
#endif

#ifdef __ia64__
/* clone(2) has a different interface on ia64, as it needs to know
   the size of the stack */
int __clone2(int (*fn)(void *),
             void *child_stack_base, size_t stack_size,
             int flags, void *arg, ...
              /* pid_t *ptid, struct user_desc *tls, pid_t *ctid */ );
#endif

uid_t firejail_uid = 0;
gid_t firejail_gid = 0;

#define STACK_SIZE (1024 * 1024)
#define STACK_ALIGNMENT 16
static char child_stack[STACK_SIZE] __attribute__((aligned(STACK_ALIGNMENT)));		// space for child's stack

Config cfg;					// configuration
int arg_command = 0;				// -c
int arg_overlay = 0;				// overlay option
int arg_overlay_keep = 0;			// place overlay diff in a known directory
int arg_overlay_reuse = 0;			// allow the reuse of overlays
int arg_rlimit_cpu = 0;				// rlimit max cpu time
int arg_rlimit_nofile = 0;			// rlimit nofile
int arg_rlimit_nproc = 0;			// rlimit nproc
int arg_rlimit_fsize = 0;				// rlimit fsize
int arg_rlimit_sigpending = 0;			// rlimit fsize
int arg_rlimit_as = 0;				// rlimit as
int arg_nogroups = 0;				// disable supplementary groups
int arg_nonewprivs = 0;			// set the NO_NEW_PRIVS prctl
int arg_noroot = 0;				// create a new user namespace and disable root user
int arg_doubledash = 0;			// double dash
int arg_shell_none = 0;			// run the program directly without a shell
int arg_private_dev = 0;			// private dev directory
int arg_keep_dev_shm = 0;                       // preserve /dev/shm
int arg_private_etc = 0;			// private etc directory
int arg_private_opt = 0;			// private opt directory
int arg_private_srv = 0;			// private srv directory
int arg_private_bin = 0;			// private bin directory
int arg_private_tmp = 0;			// private tmp directory
int arg_private_lib = 0;			// private lib directory
int arg_private_cwd = 0;			// private working directory
int arg_scan = 0;				// arp-scan all interfaces
int arg_quiet = 0;				// no output for scripting
int arg_join_network = 0;			// join only the network namespace
int arg_join_filesystem = 0;			// join only the mount namespace
int arg_nice = 0;				// nice value configured
int arg_ipc = 0;					// enable ipc namespace
int arg_writable_etc = 0;			// writable etc
int arg_writable_var = 0;			// writable var
int arg_keep_var_tmp = 0;                       // don't overwrite /var/tmp
int arg_writable_run_user = 0;			// writable /run/user
int arg_writable_var_log = 0;		// writable /var/log
int arg_allusers = 0;				// all user home directories visible
int arg_machineid = 0;				// preserve /etc/machine-id
int arg_allow_private_blacklist = 0; 		// blacklist things in private directories
int arg_disable_mnt = 0;			// disable /mnt and /media
int arg_noprofile = 0; // use default.profile if none other found/specified
int arg_memory_deny_write_execute = 0;		// block writable and executable memory
int arg_notv = 0;	// --notv
int arg_nodvd = 0; // --nodvd
int arg_nou2f = 0; // --nou2f
int arg_deterministic_exit_code = 0;	// always exit with first child's exit status
DbusPolicy arg_dbus_user = DBUS_POLICY_ALLOW;	// --dbus-user
DbusPolicy arg_dbus_system = DBUS_POLICY_ALLOW;	// --dbus-system
const char *arg_dbus_log_file = NULL;
int arg_dbus_log_user = 0;
int arg_dbus_log_system = 0;
int login_shell = 0;

int parent_to_child_fds[2];
int child_to_parent_fds[2];

char *fullargv[MAX_ARGS];			// expanded argv for restricted shell
int fullargc = 0;
static pid_t child = 0;
pid_t sandbox_pid;
mode_t orig_umask = 022;

static void clear_atexit(void) {
	EUID_ROOT();
	delete_run_files(getpid());
}

static void myexit(int rv) {
	logmsg("exiting...");
	if (!arg_command)
		fmessage("\nParent is shutting down, bye...\n");


	// delete sandbox files in shared memory
	EUID_ROOT();
	delete_run_files(sandbox_pid);
	flush_stdin();
	exit(rv);
}

static void my_handler(int s) {
	fmessage("\nParent received signal %d, shutting down the child process...\n", s);
	logsignal(s);

	if (waitpid(child, NULL, WNOHANG) == 0) {
		if (has_handler(child, s)) // signals are not delivered if there is no handler yet
			kill(child, s);
		else
			kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	myexit(s);
}

static void install_handler(void) {
	struct sigaction sga;

	// block SIGTERM while handling SIGINT
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGTERM);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGINT, &sga, NULL);

	// block SIGINT while handling SIGTERM
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sga.sa_handler = my_handler;
	sga.sa_flags = 0;
	sigaction(SIGTERM, &sga, NULL);
}


// init configuration
static void init_cfg(int argc, char **argv) {
	EUID_ASSERT();
	memset(&cfg, 0, sizeof(cfg));

	cfg.original_argv = argv;
	cfg.original_argc = argc;
	cfg.bridge0.devsandbox = "eth0";
	cfg.bridge1.devsandbox = "eth1";
	cfg.bridge2.devsandbox = "eth2";
	cfg.bridge3.devsandbox = "eth3";

	// extract user data
	EUID_ROOT(); // rise permissions for grsecurity
	struct passwd *pw = getpwuid(getuid());
	if (!pw)
		errExit("getpwuid");
	EUID_USER();
	cfg.username = strdup(pw->pw_name);
	if (!cfg.username)
		errExit("strdup");

	// check user database
	if (!firejail_user_check(cfg.username)) {
		fprintf(stderr, "Error: the user is not allowed to use Firejail.\n"
			"Please add the user in %s/firejail.users file,\n"
			"either by running \"sudo firecfg\", or by editing the file directly.\n"
			"See \"man firejail-users\" for more details.\n\n", SYSCONFDIR);

		// attempt to run the program as is
		run_symlink(argc, argv, 1);
		exit(1);
	}

	cfg.cwd = getcwd(NULL, 0);
	if (!cfg.cwd && errno != ENOENT)
		errExit("getcwd");

	// build home directory name
	if (pw->pw_dir == NULL) {
		fprintf(stderr, "Error: user %s doesn't have a user directory assigned\n", cfg.username);
		exit(1);
	}
	cfg.homedir = clean_pathname(pw->pw_dir);
	check_homedir();

	// initialize random number generator
	sandbox_pid = getpid();
	time_t t = time(NULL);
	srand(t ^ sandbox_pid);

	// arg_seccomp_error_action = EPERM;
	cfg.seccomp_error_action = "EPERM";
}

static void fix_single_std_fd(int fd, const char *file, int flags) {
	struct stat s;
	if (fstat(fd, &s) == -1 && errno == EBADF) {
		// something is wrong with fd, probably it is not opened
		int nfd = open(file, flags);
		if (nfd != fd || fstat(fd, &s) != 0)
			_exit(1); // no further attempts to fix the situation
	}
}

// glibc does this automatically if Firejail was started by a regular user
// run this for root user and as a fallback
static void fix_std_streams(void) {
	fix_single_std_fd(0, "/dev/full", O_RDONLY|O_NOFOLLOW);
	fix_single_std_fd(1, "/dev/null", O_WRONLY|O_NOFOLLOW);
	fix_single_std_fd(2, "/dev/null", O_WRONLY|O_NOFOLLOW);
}

static void check_network(Bridge *br) {
	assert(br);
	if (br->ipsandbox) { // for macvlan check network range
		char *rv = in_netrange(br->ipsandbox, br->ip, br->mask);
		if (rv) {
			fprintf(stderr, "%s", rv);
			exit(1);
		}
	}
}

#ifdef HAVE_USERNS
void check_user_namespace(void) {
	EUID_ASSERT();
	if (getuid() == 0)
		goto errout;

	// test user namespaces available in the kernel
	struct stat s1;
	struct stat s2;
	struct stat s3;
	if (stat("/proc/self/ns/user", &s1) == 0 &&
	    stat("/proc/self/uid_map", &s2) == 0 &&
	    stat("/proc/self/gid_map", &s3) == 0)
		arg_noroot = 1;
	else
		goto errout;

	return;

errout:
	fwarning("noroot option is not available\n");
	arg_noroot = 0;

}
#endif


static void exit_err_feature(const char *feature) {
	fprintf(stderr, "Error: %s feature is disabled in Firejail configuration file\n", feature);
	exit(1);
}

// run independent commands and exit program
// this function handles command line options such as --version and --help
static void run_cmd_and_exit(int i, int argc, char **argv) {
	EUID_ASSERT();

	//*************************************
	// basic arguments
	//*************************************
	if (strcmp(argv[i], "--help") == 0 ||
	    strcmp(argv[i], "-?") == 0) {
		usage();
		exit(0);
	}
	else if (strcmp(argv[i], "--version") == 0) {
		printf("firejail version %s\n", VERSION);
		printf("\n");
		print_compiletime_support();
		printf("\n");
		exit(0);
	}
	else if (strcmp(argv[i], "--list") == 0) {
		if (pid_hidepid())
			sbox_run(SBOX_ROOT| SBOX_CAPS_HIDEPID | SBOX_SECCOMP, 2, PATH_FIREMON, "--list");
		else
			sbox_run(SBOX_USER| SBOX_CAPS_NONE | SBOX_SECCOMP, 2, PATH_FIREMON, "--list");
		exit(0);
	}
	else if (strncmp(argv[i], "--join=", 7) == 0) {
		if (checkcfg(CFG_JOIN) || getuid() == 0) {
			logargs(argc, argv);

			if (arg_shell_none) {
				if (argc <= (i+1)) {
					fprintf(stderr, "Error: --shell=none set, but no command specified\n");
					exit(1);
				}
				cfg.original_program_index = i + 1;
			}

			if (!cfg.shell && !arg_shell_none)
				cfg.shell = guess_shell();

			// join sandbox by pid or by name
			pid_t pid = require_pid(argv[i] + 7);
			join(pid, argc, argv, i + 1);
			exit(0);
		}
		else
			exit_err_feature("join");

	}
}

char *guess_shell(void) {
	char *shell = NULL;
	struct stat s;

	shell = getenv("SHELL");
	if (shell) {
		invalid_filename(shell, 0); // no globbing
		if (!is_dir(shell) && strstr(shell, "..") == NULL && stat(shell, &s) == 0 && access(shell, X_OK) == 0 &&
		    strcmp(shell, PATH_FIREJAIL) != 0)
			return shell;
	}

	// shells in order of preference
	char *shells[] = {"/bin/bash", "/bin/csh", "/usr/bin/zsh", "/bin/sh", "/bin/ash", NULL };

	int i = 0;
	while (shells[i] != NULL) {
		// access call checks as real UID/GID, not as effective UID/GID
		if (stat(shells[i], &s) == 0 && access(shells[i], X_OK) == 0) {
			shell = shells[i];
			break;
		}
		i++;
	}

	return shell;
}

// return argument index
static int check_arg(int argc, char **argv, const char *argument, int strict) {
	int i;
	int found = 0;
	for (i = 1; i < argc; i++) {
		if (strict) {
			if (strcmp(argv[i], argument) == 0) {
				found = i;
				break;
			}
		}
		else {
			if (strncmp(argv[i], argument, strlen(argument)) == 0) {
				found = i;
				break;
			}
		}

		// detect end of firejail params
		if (strcmp(argv[i], "--") == 0)
			break;
		if (strncmp(argv[i], "--", 2) != 0)
			break;
	}

	return found;
}

void filter_add_errno(int fd, int syscall, int arg, void *ptrarg, bool native) {
	(void) fd;
	(void) syscall;
	(void) arg;
	(void) ptrarg;
	(void) native;
}
void filter_add_blacklist_override(int fd, int syscall, int arg, void *ptrarg, bool native) {
	(void) fd;
	(void) syscall;
	(void) arg;
	(void) ptrarg;
	(void) native;
}

static int check_postexec(const char *list) {
	char *prelist, *postlist;

	if (list) {
		syscalls_in_list(list, "@default-keep", -1, &prelist, &postlist, true);
		if (postlist)
			return 1;
	}
	return 0;
}

//*******************************************
// Main program
//*******************************************
int main(int argc, char **argv, char **envp) {
	int i;
	int prog_index = -1;			  // index in argv where the program command starts
	int lockfd_network = -1;
	int lockfd_directory = -1;
	int option_cgroup = 0;
	int custom_profile = 0;	// custom profile loaded
	int arg_caps_cmdline = 0; 	// caps requested on command line (used to break out of --chroot)
	char **ptr;

	// sanitize the umask
	orig_umask = umask(022);

	// check standard streams before printing anything
	fix_std_streams();

	// drop permissions by default and rise them when required
	EUID_INIT();
	EUID_USER();

	// argument count should be larger than 0
	if (argc == 0 || !argv || strlen(argv[0]) == 0) {
		fprintf(stderr, "Error: argv is invalid\n");
		exit(1);
	} else if (argc >= MAX_ARGS) {
		fprintf(stderr, "Error: too many arguments\n");
		exit(1);
	}

	// sanity check for arguments
	for (i = 0; i < argc; i++) {
		if (*argv[i] == 0) {
			fprintf(stderr, "Error: too short arguments\n");
			exit(1);
		}
		if (strlen(argv[i]) >= MAX_ARG_LEN) {
			fprintf(stderr, "Error: too long arguments\n");
			exit(1);
		}
		// Also remove requested environment variables
		// entirely to avoid tripping the length check below
		if (strncmp(argv[i], "--rmenv=", 8) == 0)
			unsetenv(argv[i] + 8);
	}

	// sanity check for environment variables
	for (i = 0, ptr = envp; ptr && *ptr && i < MAX_ENVS; i++, ptr++) {
		if (strlen(*ptr) >= MAX_ENV_LEN) {
			fprintf(stderr, "Error: too long environment variables, please use --rmenv\n");
			exit(1);
		}
	}
	if (i >= MAX_ENVS) {
		fprintf(stderr, "Error: too many environment variables, please use --rmenv\n");
		exit(1);
	}

	// check if the user is allowed to use firejail
	init_cfg(argc, argv);

	EUID_ROOT();
	atexit(clear_atexit);
	EUID_USER();

	// process allow-debuggers
	if (check_arg(argc, argv, "--allow-debuggers", 1)) {
		// check kernel version
		struct utsname u;
		int rv = uname(&u);
		if (rv != 0)
			errExit("uname");
		int major;
		int minor;
		if (2 != sscanf(u.release, "%d.%d", &major, &minor)) {
			fprintf(stderr, "Error: cannot extract Linux kernel version: %s\n", u.version);
			exit(1);
		}
		if (major < 4 || (major == 4 && minor < 8)) {
			fprintf(stderr, "Error: --allow-debuggers is disabled on Linux kernels prior to 4.8. "
				"A bug in ptrace call allows a full bypass of the seccomp filter. "
				"Your current kernel version is %d.%d.\n", major, minor);
			exit(1);
		}
	}

	// check argv[0] symlink wrapper if this is not a login shell
	if (*argv[0] != '-')
		run_symlink(argc, argv, 0); // if symlink detected, this function will not return

	// check if we already have a sandbox running
	// If LXC is detected, start firejail sandbox
	// otherwise try to detect a PID namespace by looking under /proc for specific kernel processes and:
	//	- start the application in a /bin/bash shell
	if (check_namespace_virt() == 0) {
		EUID_ROOT();
		int rv = check_kernel_procs();
		EUID_USER();
		if (rv == 0) {
			if (check_arg(argc, argv, "--version", 1)) {
				printf("firejail version %s\n", VERSION);
				exit(0);
			}

			// start the program directly without sandboxing
			run_no_sandbox(argc, argv);
			__builtin_unreachable();
		}
	}
	EUID_ASSERT();


	// check firejail directories
	EUID_ROOT();
	delete_run_files(sandbox_pid);
	EUID_USER();

	//check if the parent is sshd daemon
	int parent_sshd = 0;
	{
		pid_t ppid = getppid();
		EUID_ROOT();
		char *comm = pid_proc_comm(ppid);
		EUID_USER();
		if (comm) {
			if (strcmp(comm, "sshd") == 0) {
				arg_quiet = 1;
				parent_sshd = 1;
				// run sftp and scp directly without any sandboxing
				// regular login has argv[0] == "-firejail"
				if (*argv[0] != '-') {
					if (strcmp(argv[1], "-c") == 0 && argc > 2) {
						if (strcmp(argv[2], "/usr/lib/openssh/sftp-server") == 0 ||
						    strncmp(argv[2], "scp ", 4) == 0) {
							drop_privs(1);
							umask(orig_umask);
							int rv = system(argv[2]);
							exit(rv);
						}
					}
				}
			}
			free(comm);
		}
	}
	EUID_ASSERT();

	// is this a login shell, or a command passed by sshd, insert command line options from /etc/firejail/login.users
	if (*argv[0] == '-' || parent_sshd) {
		if (argc == 1)
			login_shell = 1;
		fullargc = restricted_shell(cfg.username);
		if (fullargc) {
			int j;
			for (i = 1, j = fullargc; i < argc && j < MAX_ARGS; i++, j++, fullargc++)
				fullargv[j] = argv[i];

			// replace argc/argv with fullargc/fullargv
			argv = fullargv;
			argc = j;
		}
	}
	else {
		// check --output option and execute it;
		check_output(argc, argv); // the function will not return if --output or --output-stderr option was found
	}
	EUID_ASSERT();

	// check for force-nonewprivs in /etc/firejail/firejail.config file
	if (checkcfg(CFG_FORCE_NONEWPRIVS))
		arg_nonewprivs = 1;

	// parse arguments
	for (i = 1; i < argc; i++) {
		run_cmd_and_exit(i, argc, argv); // will exit if the command is recognized
		if (strncmp(argv[i], "--cgroup=", 9) == 0) {
			if (checkcfg(CFG_CGROUP)) {
				if (option_cgroup) {
					fprintf(stderr, "Error: only a cgroup can be defined\n");
					exit(1);
				}

				option_cgroup = 1;
				cfg.cgroup = strdup(argv[i] + 9);
				if (!cfg.cgroup)
					errExit("strdup");
			        fprintf(stderr, "cgroup %s, getuid %d, geteuid %d\n", cfg.cgroup, getuid(), geteuid());
				set_cgroup(cfg.cgroup);
			}
			else
				exit_err_feature("cgroup");
		}
		else if (strcmp(argv[i], "--noprofile") == 0) {
			if (custom_profile) {
				fprintf(stderr, "Error: --profile and --noprofile options are mutually exclusive\n");
				exit(1);
			}
			arg_noprofile = 1;
		}
#ifdef HAVE_CHROOT
		else if (strncmp(argv[i], "--chroot=", 9) == 0) {
			if (checkcfg(CFG_CHROOT)) {
				if (arg_overlay) {
					fprintf(stderr, "Error: --overlay and --chroot options are mutually exclusive\n");
					exit(1);
				}

				struct stat s;
				if (stat("/proc/sys/kernel/grsecurity", &s) == 0) {
					fprintf(stderr, "Error: --chroot option is not available on Grsecurity systems\n");
					exit(1);
				}
				// extract chroot dirname
				cfg.chrootdir = argv[i] + 9;
				if (*cfg.chrootdir == '\0') {
					fprintf(stderr, "Error: invalid chroot option\n");
					exit(1);
				}
				invalid_filename(cfg.chrootdir, 0); // no globbing

				// if the directory starts with ~, expand the home directory
				if (*cfg.chrootdir == '~') {
					char *tmp;
					if (asprintf(&tmp, "%s%s", cfg.homedir, cfg.chrootdir + 1) == -1)
						errExit("asprintf");
					cfg.chrootdir = tmp;
				}
				// check chroot directory
				//fs_check_chroot_dir();
			}
			else
				exit_err_feature("chroot");
		}
#endif
		//*************************************
		// name, etc
		//*************************************
		else if (strncmp(argv[i], "--name=", 7) == 0) {
			cfg.name = argv[i] + 7;
			if (strlen(cfg.name) == 0) {
				fprintf(stderr, "Error: please provide a name for sandbox\n");
				return 1;
			}
		}
		else if (strncmp(argv[i], "--env=", 6) == 0)
			env_store(argv[i] + 6, SETENV);
		else if (strncmp(argv[i], "--rmenv=", 8) == 0)
			env_store(argv[i] + 8, RMENV);
		else {
			// double dash - positional params to follow
			if (strcmp(argv[i], "--") == 0) {
				arg_doubledash = 1;
				i++;
				if (i  >= argc) {
					fprintf(stderr, "Error: program name not found\n");
					exit(1);
				}
			}
			// is this an invalid option?
			else if (*argv[i] == '-') {
				fprintf(stderr, "Error: invalid %s command line option\n", argv[i]);
				return 1;
			}
			extract_command_name(i, argv);
			prog_index = i;
			break;
		}
	}
	EUID_ASSERT();

	// exit chroot, overlay and appimage sandboxes when caps are explicitly specified on command line
	if (getuid() != 0 && arg_caps_cmdline) {
		char *opt = NULL;
		// if (arg_appimage)
		// 	opt = "appimage";
		if (arg_overlay)
			opt = "overlay";
		else if (cfg.chrootdir)
			opt = "chroot";

		if (opt) {
			fprintf(stderr, "Error: all capabilities are dropped for %s by default.\n"
				"Please remove --caps options from the command line.\n", opt);
			exit(1);
		}
	}

	// prog_index could still be -1 if no program was specified
	if (prog_index == -1 && arg_shell_none) {
		fprintf(stderr, "Error: shell=none configured, but no program specified\n");
		exit(1);
	}
	// check user namespace (--noroot) options
	if (arg_noroot) {
		if (arg_overlay) {
			fwarning("--overlay and --noroot are mutually exclusive, --noroot disabled...\n");
			arg_noroot = 0;
		}
		else if (cfg.chrootdir) {
			fwarning("--chroot and --noroot are mutually exclusive, --noroot disabled...\n");
			arg_noroot = 0;
		}
	}

	// log command
	logargs(argc, argv);
	if (fullargc) {
		char *msg;
		if (asprintf(&msg, "user %s entering restricted shell", cfg.username) == -1)
			errExit("asprintf");
		logmsg(msg);
		free(msg);
	}

	// guess shell if unspecified
	if (!arg_shell_none && !cfg.shell) {
		cfg.shell = guess_shell();
		if (!cfg.shell) {
			fprintf(stderr, "Error: unable to guess your shell, please set explicitly by using --shell option.\n");
			exit(1);
		}
	}

	// build the sandbox command
	if (prog_index == -1 && cfg.shell) {
		assert(cfg.command_line == NULL); // runs cfg.shell
		cfg.window_title = cfg.shell;
		cfg.command_name = cfg.shell;
	}
	else {
		build_cmdline(&cfg.command_line, &cfg.window_title, argc, argv, prog_index);
	}

	assert(cfg.command_name);
	EUID_ASSERT();
	// check and assign an IP address - for macvlan it will be done again in the sandbox!
	if (any_bridge_configured()) {
		EUID_ROOT();
		lockfd_network = open(RUN_NETWORK_LOCK_FILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
		if (lockfd_network != -1) {
			int rv = fchown(lockfd_network, 0, 0);
			(void) rv;
			flock(lockfd_network, LOCK_EX);
		}

		if (cfg.bridge0.configured && cfg.bridge0.arg_ip_none == 0)
			check_network(&cfg.bridge0);
		if (cfg.bridge1.configured && cfg.bridge1.arg_ip_none == 0)
			check_network(&cfg.bridge1);
		if (cfg.bridge2.configured && cfg.bridge2.arg_ip_none == 0)
			check_network(&cfg.bridge2);
		if (cfg.bridge3.configured && cfg.bridge3.arg_ip_none == 0)
			check_network(&cfg.bridge3);

		// save network mapping in shared memory
		// network_set_run_file(sandbox_pid);
		EUID_USER();
	}
	EUID_ASSERT();

 	// create the parent-child communication pipe
 	if (pipe(parent_to_child_fds) < 0)
 		errExit("pipe");
 	if (pipe(child_to_parent_fds) < 0)
		errExit("pipe");

	if (arg_noroot && arg_overlay) {
		fwarning("--overlay and --noroot are mutually exclusive, noroot disabled\n");
		arg_noroot = 0;
	}
	else if (arg_noroot && cfg.chrootdir) {
		fwarning("--chroot and --noroot are mutually exclusive, noroot disabled\n");
		arg_noroot = 0;
	}


	// set name and x11 run files
	EUID_ROOT();
	lockfd_directory = open(RUN_DIRECTORY_LOCK_FILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (lockfd_directory != -1) {
		int rv = fchown(lockfd_directory, 0, 0);
		(void) rv;
		flock(lockfd_directory, LOCK_EX);
	}
	if (cfg.name)
		set_name_run_file(sandbox_pid);
	if (lockfd_directory != -1) {
		flock(lockfd_directory, LOCK_UN);
		close(lockfd_directory);
	}
	EUID_USER();

	// clone environment
	int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD;

	// in root mode also enable CLONE_NEWIPC
	// in user mode CLONE_NEWIPC will break MIT Shared Memory Extension (MIT-SHM)
	if (getuid() == 0 || arg_ipc) {
		flags |= CLONE_NEWIPC;
	}

	if (any_bridge_configured() || any_interface_configured()) {
		flags |= CLONE_NEWNET;
	}

	EUID_ASSERT();
	EUID_ROOT();
#ifdef __ia64__
	child = __clone2(sandbox,
		child_stack,
		STACK_SIZE,
		flags,
		NULL);
#else
	child = clone(sandbox,
		child_stack + STACK_SIZE,
		flags,
		NULL);
#endif
	if (child == -1)
		errExit("clone");
	EUID_USER();

	if (!arg_command && !arg_quiet) {
		fmessage("Parent pid %u, child pid %u\n", sandbox_pid, child);
		// print the path of the new log directory
		if (getuid() == 0) // only for root
			printf("The new log directory is /proc/%d/root/var/log\n", child);
	}

	// if (!arg_nonetwork) {
		EUID_ROOT();
		pid_t net_child = fork();
		if (net_child < 0)
			errExit("fork");
		if (net_child == 0) {
			// elevate privileges in order to get grsecurity working
			if (setreuid(0, 0))
				errExit("setreuid");
			if (setregid(0, 0))
				errExit("setregid");
			// network_main(child);
			// if (arg_debug)
			// 	printf("Host network configured\n");
#ifdef HAVE_GCOV
			__gcov_flush();
#endif
			_exit(0);
		}

		// wait for the child to finish
		waitpid(net_child, NULL, 0);
		EUID_USER();
	// }
	EUID_ASSERT();

 	// close each end of the unused pipes
 	close(parent_to_child_fds[0]);
 	close(child_to_parent_fds[1]);

	// notify child that base setup is complete
 	notify_other(parent_to_child_fds[1]);

 	// wait for child to create new user namespace with CLONE_NEWUSER
 	wait_for_other(child_to_parent_fds[0]);
 	close(child_to_parent_fds[0]);

 	if (arg_noroot) {
	 	// update the UID and GID maps in the new child user namespace
		// uid
	 	char *map_path;
	 	if (asprintf(&map_path, "/proc/%d/uid_map", child) == -1)
	 		errExit("asprintf");

	 	char *map;
	 	uid_t uid = getuid();
	 	if (asprintf(&map, "%d %d 1", uid, uid) == -1)
	 		errExit("asprintf");
 		EUID_ROOT();
	 	update_map(map, map_path);
	 	EUID_USER();
	 	free(map);
	 	free(map_path);

	 	// gid file
		if (asprintf(&map_path, "/proc/%d/gid_map", child) == -1)
			errExit("asprintf");
	 	char gidmap[1024];
	 	char *ptr = gidmap;
	 	*ptr = '\0';

	 	// add user group
	 	gid_t gid = getgid();
	 	sprintf(ptr, "%d %d 1\n", gid, gid);
	 	ptr += strlen(ptr);

	 	if (!arg_nogroups) {
		 	//  add firejail group
		 	gid_t g = get_group_id("firejail");
		 	if (g) {
		 		sprintf(ptr, "%d %d 1\n", g, g);
		 		ptr += strlen(ptr);
		 	}

		 	//  add tty group
		 	g = get_group_id("tty");
		 	if (g) {
		 		sprintf(ptr, "%d %d 1\n", g, g);
		 		ptr += strlen(ptr);
		 	}

		 	//  add audio group
		 	g = get_group_id("audio");
		 	if (g) {
		 		sprintf(ptr, "%d %d 1\n", g, g);
		 		ptr += strlen(ptr);
		 	}

		 	//  add video group
		 	g = get_group_id("video");
		 	if (g) {
		 		sprintf(ptr, "%d %d 1\n", g, g);
		 		ptr += strlen(ptr);
		 	}

		 	//  add games group
		 	g = get_group_id("games");
		 	if (g) {
		 		sprintf(ptr, "%d %d 1\n", g, g);
		 	}
		 }

 		EUID_ROOT();
	 	update_map(gidmap, map_path);
	 	EUID_USER();
	 	free(map_path);
 	}
	EUID_ASSERT();

 	// notify child that UID/GID mapping is complete
 	notify_other(parent_to_child_fds[1]);
 	close(parent_to_child_fds[1]);

 	EUID_ROOT();
	if (lockfd_network != -1) {
		flock(lockfd_network, LOCK_UN);
		close(lockfd_network);
	}
	EUID_USER();

	int status = 0;
	//*****************************
	// following code is signal-safe

	// handle CTRL-C in parent
	install_handler();

	// wait for the child to finish
	waitpid(child, &status, 0);

	// restore default signal actions
	signal(SIGTERM, SIG_DFL);
	signal(SIGINT, SIG_DFL);

	// end of signal-safe code
	//*****************************

	if (WIFEXITED(status)){
		myexit(WEXITSTATUS(status));
	} else if (WIFSIGNALED(status)) {
		myexit(WTERMSIG(status));
	} else {
		myexit(0);
	}

	return 0;
}
