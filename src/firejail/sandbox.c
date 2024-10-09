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
#include "../include/seccomp.h"
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <syscall.h>

#include <sched.h>
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER	0x10000000
#endif

#include <sys/prctl.h>
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef PR_GET_NO_NEW_PRIVS
#define PR_GET_NO_NEW_PRIVS 39
#endif

#ifdef HAVE_APPARMOR
#include <sys/apparmor.h>
#endif


static int force_nonewprivs = 0;

static int monitored_pid = 0;
static void sandbox_handler(int sig){
	usleep(10000); // don't race to print a message
	fmessage("\nChild received signal %d, shutting down the sandbox...\n", sig);

	// broadcast sigterm to all processes in the group
	kill(-1, SIGTERM);
	sleep(1);

	if (monitored_pid) {
		int monsec = 9;
		char *monfile;
		if (asprintf(&monfile, "/proc/%d/cmdline", monitored_pid) == -1)
			errExit("asprintf");
		while (monsec) {
			FILE *fp = fopen(monfile, "r");
			if (!fp)
				break;

			char c;
			size_t count = fread(&c, 1, 1, fp);
			fclose(fp);
			if (count == 0)
				break;
			sleep(1);
			monsec--;
		}
		free(monfile);
	}

	// broadcast a SIGKILL
	kill(-1, SIGKILL);
	flush_stdin();

	exit(sig);
}

static void install_handler(void) {
	struct sigaction sga;

	// block SIGTERM while handling SIGINT
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGTERM);
	sga.sa_handler = sandbox_handler;
	sga.sa_flags = 0;
	sigaction(SIGINT, &sga, NULL);

	// block SIGINT while handling SIGTERM
	sigemptyset(&sga.sa_mask);
	sigaddset(&sga.sa_mask, SIGINT);
	sga.sa_handler = sandbox_handler;
	sga.sa_flags = 0;
	sigaction(SIGTERM, &sga, NULL);
}

static void save_nogroups(void) {
	if (arg_nogroups == 0)
		return;

	FILE *fp = fopen(RUN_GROUPS_CFG, "w");
	if (fp) {
		fprintf(fp, "\n");
		SET_PERMS_STREAM(fp, 0, 0, 0644); // assume mode 0644
		fclose(fp);
	}
	else {
		fprintf(stderr, "Error: cannot save nogroups state\n");
		exit(1);
	}
}

static void save_nonewprivs(void) {
	if (arg_nonewprivs == 0)
		return;

	FILE *fp = fopen(RUN_NONEWPRIVS_CFG, "wxe");
	if (fp) {
		fprintf(fp, "\n");
		SET_PERMS_STREAM(fp, 0, 0, 0644); // assume mode 0644
		fclose(fp);
	}
	else {
		fprintf(stderr, "Error: cannot save nonewprivs state\n");
		exit(1);
	}
}

static void save_umask(void) {
	FILE *fp = fopen(RUN_UMASK_FILE, "wxe");
	if (fp) {
		fprintf(fp, "%o\n", orig_umask);
		SET_PERMS_STREAM(fp, 0, 0, 0644); // assume mode 0644
		fclose(fp);
	}
	else {
		fprintf(stderr, "Error: cannot save umask\n");
		exit(1);
	}
}

static char *create_join_file(void) {
	int fd = open(RUN_JOIN_FILE, O_RDWR|O_CREAT|O_EXCL|O_CLOEXEC, S_IRUSR | S_IWRITE | S_IRGRP | S_IROTH);
	if (fd == -1)
		errExit("open");
	if (ftruncate(fd, 1) == -1)
		errExit("ftruncate");
	char *rv = mmap(NULL, 1, PROT_WRITE, MAP_SHARED, fd, 0);
	if (rv == MAP_FAILED)
		errExit("mmap");
	close(fd);
	return rv;
}

static void sandbox_if_up(Bridge *br) {
	assert(br);
	if (!br->configured)
		return;

	char *dev = br->devsandbox;
	// net_if_up(dev);

	if (br->arg_ip_none == 1);	// do nothing
	else if (br->arg_ip_none == 0 && br->macvlan == 0) {
		if (br->ipsandbox == br->ip) {
			fprintf(stderr, "Error: %d.%d.%d.%d is interface %s address.\n", PRINT_IP(br->ipsandbox), br->dev);
			exit(1);
		}

		// just assign the address
		assert(br->ipsandbox);
		net_config_interface(dev, br->ipsandbox, br->mask, br->mtu);
		arp_announce(dev, br);
	}
	else if (br->arg_ip_none == 0 && br->macvlan == 1) {
		// reassign the macvlan address
		if (br->ipsandbox == 0)
			// ip address assigned by arp-scan for a macvlan device
			br->ipsandbox = arp_assign(dev, br); //br->ip, br->mask);
		else {
			if (br->ipsandbox == br->ip) {
				fprintf(stderr, "Error: %d.%d.%d.%d is interface %s address.\n", PRINT_IP(br->ipsandbox), br->dev);
				exit(1);
			}

			uint32_t rv = arp_check(dev, br->ipsandbox);
			if (rv) {
				fprintf(stderr, "Error: the address %d.%d.%d.%d is already in use.\n", PRINT_IP(br->ipsandbox));
				exit(1);
			}
		}
		arp_announce(dev, br);
	}
}

static void chk_chroot(void) {
	// if we are starting firejail inside some other container technology, we don't care about this
	char *mycont = getenv("container");
	if (mycont)
		return;

	// check if this is a regular chroot
	struct stat s;
	if (stat("/", &s) == 0) {
		if (s.st_ino != 2)
			return;
	}

	fprintf(stderr, "Error: cannot mount filesystem as slave\n");
	exit(1);
}

static int monitor_application(pid_t app_pid) {
	EUID_ASSERT();
	monitored_pid = app_pid;

	// block signals and install handler
	sigset_t oldmask, newmask;
	sigemptyset(&oldmask);
	sigemptyset(&newmask);
	sigaddset(&newmask, SIGTERM);
	sigaddset(&newmask, SIGINT);
	sigprocmask(SIG_BLOCK, &newmask, &oldmask);
	install_handler();

	// handle --timeout
	int options = 0;;
	unsigned timeout = 0;
	if (cfg.timeout) {
		options = WNOHANG;
		timeout = cfg.timeout;
		sleep(1);
	}

	int status = 0;
	int app_status = 0;
	while (monitored_pid) {
		usleep(20000);
		char *msg;
		if (asprintf(&msg, "monitoring pid %d\n", monitored_pid) == -1)
			errExit("asprintf");
		logmsg(msg);
		free(msg);

		pid_t rv;
		do {
			// handle signals asynchronously
			sigprocmask(SIG_SETMASK, &oldmask, NULL);

			rv = waitpid(-1, &status, options);

			// block signals again
			sigprocmask(SIG_BLOCK, &newmask, NULL);

			if (rv == -1) { // we can get here if we have processes joining the sandbox (ECHILD)
				sleep(1);
				break;
			}
			else if (rv == app_pid)
				app_status = status;

			// handle --timeout
			if (options) {
				if (--timeout == 0)  {
					// SIGTERM might fail if the process ignores it (SIG_IGN)
					// we give it 100ms to close properly and after that we SIGKILL it
					kill(-1, SIGTERM);
					usleep(100000);
					kill(-1, SIGKILL);
					flush_stdin();
					_exit(1);
				}
				else
					sleep(1);
			}
		}
		while(rv != monitored_pid);

		DIR *dir;
		if (!(dir = opendir("/proc"))) {
			// sleep 2 seconds and try again
			sleep(2);
			if (!(dir = opendir("/proc"))) {
				fprintf(stderr, "Error: cannot open /proc directory\n");
				exit(1);
			}
		}

		struct dirent *entry;
		monitored_pid = 0;
		while ((entry = readdir(dir)) != NULL) {
			unsigned pid;
			if (sscanf(entry->d_name, "%u", &pid) != 1)
				continue;
			if (pid == 1)
				continue;
			// todo: make this generic
			// Dillo browser leaves a dpid process running, we need to shut it down
			int found = 0;
			if (strcmp(cfg.command_name, "dillo") == 0) {
				char *pidname = pid_proc_comm(pid);
				if (pidname && strcmp(pidname, "dpid") == 0)
					found = 1;
				free(pidname);
			}
			if (found)
				break;

			monitored_pid = pid;
			break;
		}
		closedir(dir);
	}

	// return the appropriate exit status.
	return arg_deterministic_exit_code ? app_status : status;
}

static void print_time(void) {
	float delta = timetrace_end();
	fmessage("Child process initialized in %.02f ms\n", delta);
}


// check execute permissions for the program
// this is done typically by the shell
// we are here because of --shell=none
// we duplicate execvp functionality (man execvp):
//	[...] if  the  specified
//	filename  does  not contain a slash (/) character. The file is sought
//	in the colon-separated list of directory pathnames  specified  in  the
//	PATH  environment  variable.
static int ok_to_run(const char *program) {
	if (strstr(program, "/")) {
		if (access(program, X_OK) == 0) // it will also dereference symlinks
			return 1;
	}
	else { // search $PATH
		char *path1 = getenv("PATH");
		if (path1) {
			char *path2 = strdup(path1);
			if (!path2)
				errExit("strdup");

			// use path2 to count the entries
			char *ptr = strtok(path2, ":");
			while (ptr) {
				char *fname;

				if (asprintf(&fname, "%s/%s", ptr, program) == -1)
					errExit("asprintf");
				struct stat s;
				int rv = stat(fname, &s);
				if (rv == 0) {
					if (access(fname, X_OK) == 0) {
						free(path2);
						free(fname);
						return 1;
					}
					else
						fprintf(stderr, "Error: execute permission denied for %s\n", fname);

					free(fname);
					break;
				}

				free(fname);
				ptr = strtok(NULL, ":");
			}
			free(path2);
		}
	}
	return 0;
}

void start_application(int no_sandbox, int fd, char *set_sandbox_status) {
	// set environment
	if (no_sandbox == 0) {
		env_defaults();
		env_apply();
	}
	// restore original umask
	umask(orig_umask);
	//****************************************
	// start the program without using a shell
	//****************************************
	if (arg_shell_none) {
		if (cfg.original_program_index == 0) {
			fprintf(stderr, "Error: --shell=none configured, but no program specified\n");
			exit(1);
		}

		if (!arg_command && !arg_quiet)
			print_time();

		if (ok_to_run(cfg.original_argv[cfg.original_program_index]) == 0) {
			fprintf(stderr, "Error: no suitable %s executable found\n", cfg.original_argv[cfg.original_program_index]);
			exit(1);
		}

		if (set_sandbox_status)
			*set_sandbox_status = SANDBOX_DONE;
		execvp(cfg.original_argv[cfg.original_program_index], &cfg.original_argv[cfg.original_program_index]);
	}
	//****************************************
	// start the program using a shell
	//****************************************
	else {
		assert(cfg.shell);

		char *arg[5];
		int index = 0;
		arg[index++] = cfg.shell;
		if (cfg.command_line) {
			arg[index++] = "-c";
			if (arg_doubledash)
				arg[index++] = "--";
			arg[index++] = cfg.command_line;
		}
		else if (login_shell) {
			arg[index++] = "-l";
		}

		assert(index < 5);
		arg[index] = NULL;

		if (!arg_command && !arg_quiet)
			print_time();
		if (set_sandbox_status)
			*set_sandbox_status = SANDBOX_DONE;
		execvp(arg[0], arg);

		// join sandbox without shell in the mount namespace
		if (fd > -1)
			fexecve(fd, arg, environ);
	}

	perror("Cannot start application");
	exit(1);
}

static void enforce_filters(void) {
	// enforce NO_NEW_PRIVS
	arg_nonewprivs = 1;
	force_nonewprivs = 1;

	// disable all capabilities
	fmessage("\n**     Warning: dropping all Linux capabilities     **\n\n");
	arg_nogroups = 1;
}

void fork_run_wait(char **argv, char *res, int pdeathsig) {
    pid_t fpid; //fpid表示fork函数返回的值
    int ret = 0;
    char *command = argv[0];
    char **arg_list = argv;
    int pipefd[2];
    size_t len = 0;

    ret = pipe(pipefd);

    fpid = fork();

    if (fpid < 0) {
        errExit("fork_run_wait");
    }
    else if (fpid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        if (pdeathsig) {
            prctl(PR_SET_PDEATHSIG,SIGTERM);
        }

        ret = execvp(command, arg_list);
        if (ret == -1 ) {
            errExit("fork_run_wait");
        }
    }
    close(pipefd[1]);
    if(res) {
        ssize_t count;
        while ((count = read(pipefd[0], res, 1024)) > 0) {
            if(strstr(res, "unix:")) {
                len = strlen(res);
                res[len-1] = '\0';
                break;
            }
        }
    }
    close(pipefd[0]);
}

int sandbox(void* sandbox_arg) {
	// Get rid of unused parameter warning
	(void)sandbox_arg;

	pid_t child_pid = getpid();

 	// close each end of the unused pipes
 	close(parent_to_child_fds[1]);
 	close(child_to_parent_fds[0]);

 	// wait for parent to do base setup
 	wait_for_other(parent_to_child_fds[0]);

	//****************************
	// set hostname
	//****************************
	if (cfg.hostname) {
		if (sethostname(cfg.hostname, strlen(cfg.hostname)) < 0)
			errExit("sethostname");
	}

	//****************************
	// mount namespace
	//****************************
	// mount events are not forwarded between the host the sandbox
	if (mount(NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) < 0) {
		chk_chroot();
	}
	// ... and mount a tmpfs on top of /run/firejail/mnt directory
	preproc_mount_mnt_dir();
	// bind-mount firejail binaries and helper programs
	if (mount(LIBDIR "/firejail", RUN_FIREJAIL_LIB_DIR, NULL, MS_BIND, NULL) < 0 ||
	    mount(NULL, RUN_FIREJAIL_LIB_DIR, NULL, MS_RDONLY|MS_NOSUID|MS_NODEV|MS_BIND|MS_REMOUNT, NULL) < 0)
		errExit("mounting " RUN_FIREJAIL_LIB_DIR);
	// keep a copy of dhclient executable before the filesystem is modified

	//****************************
	// log sandbox data
	//****************************
	if (cfg.name)
		fs_logger2("sandbox name:", cfg.name);
	fs_logger2int("sandbox pid:", (int) sandbox_pid);
	if (cfg.chrootdir)
		fs_logger("sandbox filesystem: chroot");
	else if (arg_overlay)
		fs_logger("sandbox filesystem: overlay");
	else
		fs_logger("sandbox filesystem: local");
	fs_logger("install mount namespace");

	//****************************
	// fs pre-processing:
	//  - build seccomp filters
	//  - create an empty /etc/ld.so.preload
	//****************************
	if (cfg.protocol) {
		// build the seccomp filter as a regular user
		int rv = sbox_run(SBOX_USER | SBOX_CAPS_NONE | SBOX_SECCOMP, 5,
			PATH_FSECCOMP, "protocol", "build", cfg.protocol, RUN_SECCOMP_PROTOCOL);
		if (rv)
			exit(rv);
	}

	// need ld.so.preload if tracing or seccomp with any non-default lists
	// bool need_preload = arg_trace || arg_tracelog || arg_seccomp_postexec;
	// for --appimage, --chroot and --overlay* we force NO_NEW_PRIVS
	// and drop all capabilities
	if (getuid() != 0 && (cfg.chrootdir || arg_overlay)) {
		enforce_filters();
	}
	// store hosts file
	if (cfg.hosts_file)
		fs_store_hosts_file();

	//****************************
	// configure filesystem
	//****************************
#ifdef HAVE_CHROOT
	if (cfg.chrootdir) {
		fs_chroot(cfg.chrootdir);
	}
	else
#endif
#ifdef HAVE_OVERLAYFS
	if (arg_overlay)
		fs_overlayfs();
#endif
	if (arg_private_dev)
		fs_private_dev();

	if (arg_private_opt) {
		if (cfg.chrootdir)
			fwarning("private-opt feature is disabled in chroot\n");
		else if (arg_overlay)
			fwarning("private-opt feature is disabled in overlay\n");
		else {
			fs_private_dir_list("/opt", RUN_OPT_DIR, cfg.opt_private_keep);
		}
	}

	if (arg_private_srv) {
		if (cfg.chrootdir)
			fwarning("private-srv feature is disabled in chroot\n");
		else if (arg_overlay)
			fwarning("private-srv feature is disabled in overlay\n");
		else {
			fs_private_dir_list("/srv", RUN_SRV_DIR, cfg.srv_private_keep);
		}
	}

	// private-bin is disabled for appimages
	if (arg_private_bin) {
		if (cfg.chrootdir)
			fwarning("private-bin feature is disabled in chroot\n");
		else if (arg_overlay)
			fwarning("private-bin feature is disabled in overlay\n");
		else {
			fs_private_bin_list();
		}
	}

	// private-lib is disabled for appimages
	if (arg_private_lib) {
		if (cfg.chrootdir)
			fwarning("private-lib feature is disabled in chroot\n");
		else if (arg_overlay)
			fwarning("private-lib feature is disabled in overlay\n");
		else {
			fs_private_lib();
		}
	}
	//****************************
	// hosts and hostname
	//****************************
	if (cfg.hostname)
		fs_hostname(cfg.hostname);

	if (cfg.hosts_file)
		fs_mount_hosts_file();

	// Install new /etc last, so we can use it as long as possible
	if (arg_private_etc) {
		if (cfg.chrootdir)
			fwarning("private-etc feature is disabled in chroot\n");
		else if (arg_overlay)
			fwarning("private-etc feature is disabled in overlay\n");
		else {
			fs_private_dir_list("/etc", RUN_ETC_DIR, cfg.etc_private_keep);
			fs_private_dir_list("/usr/etc", RUN_USR_ETC_DIR, cfg.etc_private_keep); // openSUSE
			// create /etc/ld.so.preload file again
			// if (need_preload)
			// 	fs_trace_preload();
		}
	}
	//****************************
	// set dns
	//****************************
	fs_resolvconf();

	//****************************
	// fs post-processing
	//****************************
	fs_logger_print();
	fs_logger_change_owner();

	//****************************
	// set application environment
	//****************************
	EUID_USER();
	int cwd = 0;
	if (cfg.cwd) {
		if (chdir(cfg.cwd) == 0)
			cwd = 1;
		else if (arg_private_cwd) {
			fprintf(stderr, "Error: unable to enter private working directory: %s: %s\n", cfg.cwd, strerror(errno));
			exit(1);
		}
	}

	if (!cwd) {
		if (chdir("/") < 0)
			errExit("chdir");
		if (cfg.homedir) {
			struct stat s;
			if (stat(cfg.homedir, &s) == 0) {
				/* coverity[toctou] */
				if (chdir(cfg.homedir) < 0)
					errExit("chdir");
			}
		}
	}
	EUID_ROOT();
	// save original umask
	save_umask();

	//****************************
	// set security filters
	//****************************
	// save state of nonewprivs
	save_nonewprivs();

	// save cgroup in CGROUP_CFG file
	save_cgroup();

	//****************************************
	// relay status information to join option
	//****************************************

	char *set_sandbox_status = create_join_file();

	//****************************************
	// create a new user namespace
	//     - too early to drop privileges
	//****************************************
	save_nogroups();
	if (arg_noroot) {
		int rv = unshare(CLONE_NEWUSER);
		if (rv == -1) {
			fwarning("cannot create a new user namespace, going forward without it...\n");
			arg_noroot = 0;
		}
	}

	// notify parent that new user namespace has been created so a proper
 	// UID/GID map can be setup
 	notify_other(child_to_parent_fds[1]);
 	close(child_to_parent_fds[1]);

 	// wait for parent to finish setting up a proper UID/GID map
 	wait_for_other(parent_to_child_fds[0]);
 	close(parent_to_child_fds[0]);

	//****************************************
	// Set NO_NEW_PRIVS if desired
	//****************************************
	if (arg_nonewprivs) {
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

		if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
			fwarning("cannot set NO_NEW_PRIVS, it requires a Linux kernel version 3.5 or newer.\n");
			if (force_nonewprivs) {
				fprintf(stderr, "Error: NO_NEW_PRIVS required for this sandbox, exiting ...\n");
				exit(1);
			}
		}
	}

	//****************************************
	// drop privileges
	//****************************************
	drop_privs(arg_nogroups);

	// kill the sandbox in case the parent died
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	//****************************************
	// fork the application and monitor it
	//****************************************
	pid_t app_pid = fork();
	if (app_pid == -1)
		errExit("fork");

	if (app_pid == 0) {
		// set nice and rlimits
		if (arg_nice)
			set_nice(cfg.nice);
		set_rlimits();

		start_application(0, -1, set_sandbox_status);
	}

	munmap(set_sandbox_status, 1);

	int status = monitor_application(app_pid);	// monitor application
	flush_stdin();

	if (WIFEXITED(status)) {
		// if we had a proper exit, return that exit status
		return WEXITSTATUS(status);
	} else {
		// something else went wrong!
		return -1;
	}
}
