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
#ifndef FIREJAIL_H
#define FIREJAIL_H
#include "../include/common.h"
#include "../include/euid_common.h"
#include "../include/rundefs.h"
#include <stdarg.h>
#include <sys/stat.h>

// profiles
#define DEFAULT_USER_PROFILE	"default"
#define DEFAULT_ROOT_PROFILE	"server"
#define MAX_INCLUDE_LEVEL 16		// include levels in profile files


#define ASSERT_PERMS(file, uid, gid, mode) \
	do { \
		assert(file);\
		struct stat s;\
		if (stat(file, &s) == -1) errExit("stat");\
		assert(s.st_uid == uid);\
		assert(s.st_gid == gid);\
		assert((s.st_mode & 07777) == (mode));\
	} while (0)
#define ASSERT_PERMS_FD(fd, uid, gid, mode) \
	do { \
		struct stat s;\
		if (fstat(fd, &s) == -1) errExit("fstat");\
		assert(s.st_uid == uid);\
		assert(s.st_gid == gid);\
		assert((s.st_mode & 07777) == (mode));\
	} while (0)
#define ASSERT_PERMS_STREAM(file, uid, gid, mode) \
	do { \
		int fd = fileno(file);\
		if (fd == -1) errExit("fileno");\
		ASSERT_PERMS_FD(fd, uid, gid, (mode));\
	} while (0)

#define SET_PERMS_FD(fd, uid, gid, mode) \
	do { \
		if (fchmod(fd, (mode)) == -1)	errExit("chmod");\
		if (fchown(fd, uid, gid) == -1) errExit("chown");\
	} while (0)
#define SET_PERMS_STREAM(stream, uid, gid, mode) \
	do { \
		int fd = fileno(stream);\
		if (fd == -1) errExit("fileno");\
		SET_PERMS_FD(fd, uid, gid, (mode));\
	} while (0)
#define SET_PERMS_STREAM_NOERR(stream, uid, gid, mode) \
	do { \
		int fd = fileno(stream);\
		if (fd == -1) continue;\
		int rv = fchmod(fd, (mode));\
		(void) rv;\
		rv = fchown(fd, uid, gid);\
		(void) rv;\
	} while (0)

// main.c
typedef struct bridge_t {
	// on the host
	char *dev;		// interface device name: bridge or regular ethernet
	uint32_t ip;		// interface device IP address
	uint32_t mask;		// interface device mask
	uint8_t mac[6];		// interface mac address
	int mtu;		// interface mtu

	char *veth_name;	// veth name for the device connected to the bridge

	// inside the sandbox
	char *devsandbox;	// name of the device inside the sandbox
	uint32_t ipsandbox;	// ip address inside the sandbox
	uint32_t masksandbox;	// network mask inside the sandbox
	char *ip6sandbox;	// ipv6 address inside the sandbox
	uint8_t macsandbox[6]; // mac address inside the sandbox
	uint32_t iprange_start;// iprange arp scan start range
	uint32_t iprange_end;	// iprange arp scan end range

	// flags
	uint8_t arg_ip_none;	// --ip=none
	uint8_t arg_ip_dhcp;
	uint8_t arg_ip6_dhcp;
	uint8_t macvlan;	// set by --net=eth0 (or eth1, ...); reset by --net=br0 (or br1, ...)
	uint8_t configured;
	uint8_t scan;		// set by --scan
}  Bridge;

typedef struct interface_t {
	char *dev;
	uint32_t ip;
	uint32_t mask;
	uint8_t mac[6];
	int mtu;

	uint8_t configured;
} Interface;

typedef struct profile_entry_t {
	struct profile_entry_t *next;
	char *data;	// command

	// whitelist command parameters
	char *link;	// link name - set if the file is a link
	enum {
		WLDIR_HOME = 1,	// whitelist in home directory
		WLDIR_TMP,	// whitelist in /tmp directory
		WLDIR_MEDIA,	// whitelist in /media directory
		WLDIR_MNT,	// whitelist in /mnt directory
		WLDIR_VAR,	// whitelist in /var directory
		WLDIR_DEV,	// whitelist in /dev directory
		WLDIR_OPT,	// whitelist in /opt directory
		WLDIR_SRV,	// whitelist in /srv directory
		WLDIR_ETC,	// whitelist in /etc directory
		WLDIR_SHARE,	// whitelist in /usr/share directory
		WLDIR_MODULE,	// whitelist in /sys/module directory
		WLDIR_RUN	// whitelist in /run/user/$uid directory
	} wldir;
} ProfileEntry;

typedef struct config_t {
	// user data
	char *username;
	char *homedir;

	// filesystem
	ProfileEntry *profile;
#define MAX_PROFILE_IGNORE 32
	char *profile_ignore[MAX_PROFILE_IGNORE];
	char *chrootdir;	// chroot directory
	char *home_private;	// private home directory
	char *home_private_keep;	// keep list for private home directory
	char *etc_private_keep;	// keep list for private etc directory
	char *opt_private_keep;	// keep list for private opt directory
	char *srv_private_keep;	// keep list for private srv directory
	char *bin_private_keep;	// keep list for private bin directory
	char *bin_private_lib;	// executable list sent by private-bin to private-lib
	char *lib_private_keep;	// keep list for private bin directory
	char *cwd;		// current working directory
	char *overlay_dir;

	// networking
	char *name;		// sandbox name
	char *hostname;	// host name
	char *hosts_file;		// hosts file to be installed in the sandbox
	uint32_t defaultgw;	// default gateway
	Bridge bridge0;
	Bridge bridge1;
	Bridge bridge2;
	Bridge bridge3;
	Interface interface0;
	Interface interface1;
	Interface interface2;
	Interface interface3;
	char *dns1;	// up to 4 IP (v4/v6) addresses for dns servers
	char *dns2;
	char *dns3;
	char *dns4;

	// seccomp
	char *seccomp_list, *seccomp_list32;		// optional seccomp list on top of default filter
	char *seccomp_list_drop, *seccomp_list_drop32;	// seccomp drop list
	char *seccomp_list_keep, *seccomp_list_keep32;	// seccomp keep list
	char *protocol;			// protocol list
	char *seccomp_error_action;			// error action: kill, log or errno

	// rlimits
	long long unsigned rlimit_cpu;
	long long unsigned rlimit_nofile;
	long long unsigned rlimit_nproc;
	long long unsigned rlimit_fsize;
	long long unsigned rlimit_sigpending;
	long long unsigned rlimit_as;
	unsigned timeout;	// maximum time elapsed before killing the sandbox

	// cpu affinity, nice and control groups
	uint32_t cpus;
	int nice;
	char *cgroup;

	// command line
	char *command_line;
	char *window_title;
	char *command_name;
	char *shell;
	char **original_argv;
	int original_argc;
	int original_program_index;
} Config;
extern Config cfg;

static inline Bridge *last_bridge_configured(void) {
	if (cfg.bridge3.configured)
		return &cfg.bridge3;
	else if (cfg.bridge2.configured)
		return &cfg.bridge2;
	else if (cfg.bridge1.configured)
		return &cfg.bridge1;
	else if (cfg.bridge0.configured)
		return &cfg.bridge0;
	else
		return NULL;
}

static inline int any_bridge_configured(void) {
	if (cfg.bridge0.configured || cfg.bridge1.configured || cfg.bridge2.configured || cfg.bridge3.configured)
		return 1;
	else
		return 0;
}

static inline int any_interface_configured(void) {
	if (cfg.interface0.configured || cfg.interface1.configured || cfg.interface2.configured || cfg.interface3.configured)
		return 1;
	else
		return 0;
}

static inline int any_ip_dhcp(void) {
	if (cfg.bridge0.arg_ip_dhcp || cfg.bridge1.arg_ip_dhcp || cfg.bridge2.arg_ip_dhcp || cfg.bridge3.arg_ip_dhcp)
		return 1;
	else
		return 0;
}

static inline int any_ip6_dhcp(void) {
	if (cfg.bridge0.arg_ip6_dhcp || cfg.bridge1.arg_ip6_dhcp || cfg.bridge2.arg_ip6_dhcp || cfg.bridge3.arg_ip6_dhcp)
		return 1;
	else
		return 0;
}

static inline int any_dhcp(void) {
  return any_ip_dhcp() || any_ip6_dhcp();
}

extern int arg_private_cache;	// private home/.cache
extern int arg_debug_blacklists;	// print debug messages for blacklists
extern int arg_debug_whitelists;	// print debug messages for whitelists
extern int arg_debug_private_lib;	// print debug messages for private-lib
extern int arg_command;	// -c
extern int arg_overlay;		// overlay option
extern int arg_overlay_keep;	// place overlay diff in a known directory
extern int arg_overlay_reuse;	// allow the reuse of overlays

extern int arg_seccomp32;	// enable default seccomp filter for 32 bit arch

extern int arg_caps_default_filter;	// enable default capabilities filter
extern int arg_caps_drop;		// drop list
extern int arg_caps_keep;		// keep list
extern char *arg_caps_list;		// optional caps list

extern char *arg_tracefile;	// syscall tracing file
extern int arg_rlimit_cpu;	// rlimit cpu
extern int arg_rlimit_nofile;	// rlimit nofile
extern int arg_rlimit_nproc;	// rlimit nproc
extern int arg_rlimit_fsize;	// rlimit fsize
extern int arg_rlimit_sigpending;// rlimit sigpending
extern int arg_rlimit_as;	//rlimit as
extern int arg_nogroups;	// disable supplementary groups
extern int arg_nonewprivs;	// set the NO_NEW_PRIVS prctl
extern int arg_noroot;		// create a new user namespace and disable root user
extern int arg_netfilter;	// enable netfilter
extern int arg_netfilter6;	// enable netfilter6
extern char *arg_netfilter_file;	// netfilter file
extern char *arg_netfilter6_file;	// netfilter file
extern char *arg_netns;		// "ip netns"-created network namespace to use
extern int arg_doubledash;	// double dash
extern int arg_shell_none;	// run the program directly without a shell
extern int arg_private_dev;	// private dev directory
extern int arg_keep_dev_shm;    // preserve /dev/shm
extern int arg_private_etc;	// private etc directory
extern int arg_private_opt;	// private opt directory
extern int arg_private_srv;	// private srv directory
extern int arg_private_bin;	// private bin directory
extern int arg_private_tmp;	// private tmp directory
extern int arg_private_lib;	// private lib directory
extern int arg_private_cwd;	// private working directory
extern int arg_scan;		// arp-scan all interfaces
extern int arg_whitelist;	// whitelist command
extern int arg_noautopulse; // disable automatic ~/.config/pulse init
extern int arg_quiet;		// no output for scripting
extern int arg_join_network;	// join only the network namespace
extern int arg_join_filesystem;	// join only the mount namespace
extern int arg_nice;		// nice value configured
extern int arg_ipc;		// enable ipc namespace
extern int arg_writable_etc;	// writable etc
extern int arg_writable_var;	// writable var
extern int arg_keep_var_tmp; // don't overwrite /var/tmp
extern int arg_writable_run_user;	// writable /run/user
extern int arg_writable_var_log; // writable /var/log
extern int arg_apparmor;	// apparmor
extern int arg_allusers;	// all user home directories visible
extern int arg_machineid;	// preserve /etc/machine-id
extern int arg_disable_mnt;	// disable /mnt and /media
extern int arg_noprofile;	// use default.profile if none other found/specified
extern int arg_memory_deny_write_execute;	// block writable and executable memory
extern int arg_notv;	// --notv
extern int arg_nodvd;	// --nodvd
extern int arg_nou2f;   // --nou2f
extern int arg_deterministic_exit_code;	// always exit with first child's exit status

typedef enum {
	DBUS_POLICY_ALLOW,	// Allow unrestricted access to the bus
	DBUS_POLICY_FILTER, // Filter with xdg-dbus-proxy
	DBUS_POLICY_BLOCK   // Block access
} DbusPolicy;
extern DbusPolicy arg_dbus_user; // --dbus-user
extern DbusPolicy arg_dbus_system; // --dbus-system
extern int arg_dbus_log_user;
extern int arg_dbus_log_system;
extern const char *arg_dbus_log_file;

extern int login_shell;
extern int parent_to_child_fds[2];
extern int child_to_parent_fds[2];
extern pid_t sandbox_pid;
extern mode_t orig_umask;
extern unsigned long long start_timestamp;

#define MAX_ARGS 128		// maximum number of command arguments (argc)
#define MAX_ARG_LEN (PATH_MAX + 32) // --foobar=PATH
extern char *fullargv[MAX_ARGS];
extern int fullargc;

// main.c
void check_user_namespace(void);
char *guess_shell(void);

// sandbox.c
#define SANDBOX_DONE '1'
int sandbox(void* sandbox_arg);
void start_application(int no_sandbox, int fd, char *set_sandbox_status) __attribute__((noreturn));

// preproc.c
void preproc_build_firejail_dir(void);
void preproc_mount_mnt_dir(void);
void preproc_clean_run(void);

// fs.c
typedef enum {
	BLACKLIST_FILE,
	BLACKLIST_NOLOG,
	MOUNT_READONLY,
	MOUNT_TMPFS,
	MOUNT_NOEXEC,
	MOUNT_RDWR,
	MOUNT_RDWR_NOCHECK, // no check of ownership
	OPERATION_MAX
} OPERATION;

// chroot.c
// chroot into an existing directory; mount existing /dev and update /etc/resolv.conf
void fs_check_chroot_dir(void);
void fs_chroot(const char *rootdir);

// usage.c
void usage(void);

// join.c
void join(pid_t pid, int argc, char **argv, int index) __attribute__((noreturn));
bool is_ready_for_join(const pid_t pid);
void check_join_permission(pid_t pid);
pid_t switch_to_child(pid_t pid);

// restricted_shell.c
int restricted_shell(const char *user);

// macros.c
char *expand_macros(const char *path);
char *resolve_macro(const char *name);
void invalid_filename(const char *fname, int globbing);
int is_macro(const char *name);
int macro_id(const char *name);


// util.c
void errLogExit(char* fmt, ...) __attribute__((noreturn));
void fwarning(char* fmt, ...);
void fmessage(char* fmt, ...);
void drop_privs(int nogroups);
int mkpath_as_root(const char* path);
void extract_command_name(int index, char **argv);
void logsignal(int s);
void logmsg(const char *msg);
void logargs(int argc, char **argv) ;
void logerr(const char *msg);
void set_nice(int inc);
int copy_file(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
void copy_file_as_user(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
void copy_file_from_user_to_root(const char *srcname, const char *destname, uid_t uid, gid_t gid, mode_t mode);
void touch_file_as_user(const char *fname, mode_t mode);
int is_dir(const char *fname);
int is_link(const char *fname);
void trim_trailing_slash_or_dot(char *path);
char *line_remove_spaces(const char *buf);
char *split_comma(char *str);
char *clean_pathname(const char *path);
void check_unsigned(const char *str, const char *msg);
int find_child(pid_t parent, pid_t *child);
void update_map(char *mapping, char *map_file);
void wait_for_other(int fd);
void notify_other(int fd);
uid_t pid_get_uid(pid_t pid);
uid_t get_group_id(const char *group);
int remove_overlay_directory(void);
void flush_stdin(void);
int create_empty_dir_as_user(const char *dir, mode_t mode);
void create_empty_dir_as_root(const char *dir, mode_t mode);
void create_empty_file_as_root(const char *dir, mode_t mode);
int set_perms(const char *fname, uid_t uid, gid_t gid, mode_t mode);
void mkdir_attr(const char *fname, mode_t mode, uid_t uid, gid_t gid);
unsigned extract_timeout(const char *str);
void disable_file_or_dir(const char *fname);
void disable_file_path(const char *path, const char *file);
int safe_fd(const char *path, int flags);
int has_handler(pid_t pid, int signal);
void enter_network_namespace(pid_t pid);
int read_pid(const char *name, pid_t *pid);
pid_t require_pid(const char *name);
void check_homedir(void);

// Get info regarding the last kernel mount operation from /proc/self/mountinfo
// The return value points to a static area, and will be overwritten by subsequent calls.
// The function does an exit(1) if anything goes wrong.
typedef struct {
	int mountid; // id of the mount
	char *fsname; // the pathname of the directory in the filesystem which forms the root of this mount
	char *dir;	// mount destination
	char *fstype; // filesystem type
} MountData;

// mountinfo.c
MountData *get_last_mount(void);
int get_mount_id(const char *path);
char **build_mount_array(const int mount_id, const char *path);

// fs_var.c
void fs_var_log(void);	// mounting /var/log
void fs_var_lib(void);	// various other fixes for software in /var directory
void fs_var_cache(void); // various other fixes for software in /var/cache directory
// void fs_var_run(void);
void fs_var_lock(void);
void fs_var_tmp(void);
void fs_var_utmp(void);
void dbg_test_dir(const char *dir);

// fs_dev.c
void fs_dev_shm(void);
void fs_private_dev(void);
void fs_dev_disable_sound(void);
void fs_dev_disable_3d(void);
void fs_dev_disable_video(void);
void fs_dev_disable_tv(void);
void fs_dev_disable_dvd(void);
void fs_dev_disable_u2f(void);

// fs_home.c
// private mode (--private)
void fs_private(void);
// private mode (--private=homedir)
void fs_private_homedir(void);
// check new private home directory (--private= option) - exit if it fails
void fs_check_private_dir(void);
// check new private working directory (--private-cwd= option) - exit if it fails
void fs_check_private_cwd(const char *dir);
void fs_private_home_list(void);

// fs_trace.c
void fs_trace_preload(void);
void fs_tracefile(void);
void fs_trace(void);

// fs_hostname.c
void fs_hostname(const char *hostname);
void fs_resolvconf(void);
char *fs_check_hosts_file(const char *fname);
void fs_store_hosts_file(void);
void fs_mount_hosts_file(void);

// rlimit.c
void set_rlimits(void);

// cgroup.c
void save_cgroup(void);
void load_cgroup(const char *fname);
void set_cgroup(const char *path);

// output.c
void check_output(int argc, char **argv);

// fs_etc.c
void fs_machineid(void);
void fs_private_dir_list(const char *private_dir, const char *private_run_dir, const char *private_list);

// no_sandbox.c
int check_namespace_virt(void);
int check_kernel_procs(void);
void run_no_sandbox(int argc, char **argv) __attribute__((noreturn));

#define MAX_ENVS 256			// some sane maximum number of environment variables
#define MAX_ENV_LEN (PATH_MAX + 32)	// FOOBAR=SOME_PATH
// env.c
typedef enum {
	SETENV = 0,
	RMENV
} ENV_OP;

void env_store(const char *str, ENV_OP op);
void env_apply(void);
void env_defaults(void);

// fs_bin.c
void fs_private_bin_list(void);

// fs_lib.c
void fs_private_lib(void);

// restrict_users.c
void restrict_users(void);

// fs_logger.c
void fs_logger(const char *msg);
void fs_logger2(const char *msg1, const char *msg2);
void fs_logger2int(const char *msg1, int d);
void fs_logger3(const char *msg1, const char *msg2, const char *msg3);
void fs_logger_print(void);
void fs_logger_change_owner(void);
void fs_logger_print_log(pid_t pid) __attribute__((noreturn));

// run_symlink.c
void run_symlink(int argc, char **argv, int run_as_is);

// paths.c
char **build_paths(void);
unsigned int count_paths(void);
int program_in_path(const char *program);

// fs_mkdir.c
void fs_mkdir(const char *name);
void fs_mkfile(const char *name);

// checkcfg.c
#define DEFAULT_ARP_PROBES 2
enum {
	CFG_FILE_TRANSFER = 0,
	CFG_X11,
	CFG_BIND,
	CFG_USERNS,
	CFG_CHROOT,
	CFG_SECCOMP,
	CFG_NETWORK,
	CFG_RESTRICTED_NETWORK,
	CFG_FORCE_NONEWPRIVS,
	CFG_WHITELIST,
	CFG_XEPHYR_WINDOW_TITLE,
	CFG_OVERLAYFS,
	CFG_PRIVATE_HOME,
	CFG_PRIVATE_BIN_NO_LOCAL,
	CFG_FIREJAIL_PROMPT,
	CFG_FOLLOW_SYMLINK_AS_USER,
	CFG_DISABLE_MNT,
	CFG_JOIN,
	CFG_ARP_PROBES,
	CFG_XPRA_ATTACH,
	CFG_BROWSER_DISABLE_U2F,
	CFG_BROWSER_ALLOW_DRM,
	CFG_PRIVATE_LIB,
	CFG_APPARMOR,
	CFG_DBUS,
	CFG_PRIVATE_CACHE,
	CFG_CGROUP,
	CFG_NAME_CHANGE,
	CFG_SECCOMP_ERROR_ACTION,
	// CFG_FILE_COPY_LIMIT - file copy limit handled using setenv/getenv
	CFG_MAX // this should always be the last entry
};
extern char *xephyr_screen;
extern char *xephyr_extra_params;
extern char *xpra_extra_params;
extern char *xvfb_screen;
extern char *xvfb_extra_params;
extern char *netfilter_default;
extern unsigned long join_timeout;
extern char *config_seccomp_error_action_str;

int checkcfg(int val);
void print_compiletime_support(void);

// appimage_size.c
long unsigned int appimage2_size(const char *fname);

// cmdline.c
void build_cmdline(char **command_line, char **window_title, int argc, char **argv, int index);
void build_appimage_cmdline(char **command_line, char **window_title, int argc, char **argv, int index, char *apprun_path);

// sbox.c
// programs
#define PATH_FNET_MAIN (LIBDIR "/firejail/fnet")		// when called from main thread
#define PATH_FNET (RUN_FIREJAIL_LIB_DIR "/fnet")	// when called from sandbox thread

//#define PATH_FNETFILTER (LIBDIR "/firejail/fnetfilter")
#define PATH_FNETFILTER (RUN_FIREJAIL_LIB_DIR "/fnetfilter")

#define PATH_FIREMON (PREFIX "/bin/firemon")
#define PATH_FIREJAIL (PREFIX "/bin/firejail")

#define PATH_FSECCOMP_MAIN (LIBDIR "/firejail/fseccomp")		// when called from main thread
#define PATH_FSECCOMP ( RUN_FIREJAIL_LIB_DIR "/fseccomp")	// when called from sandbox thread

// FSEC_PRINT is run outside of sandbox by --seccomp.print
// it is also run from inside the sandbox by --debug; in this case we do an access(filename, X_OK) test first
#define PATH_FSEC_PRINT (LIBDIR "/firejail/fsec-print")

//#define PATH_FSEC_OPTIMIZE (LIBDIR "/firejail/fsec-optimize")
#define PATH_FSEC_OPTIMIZE (RUN_FIREJAIL_LIB_DIR "/fsec-optimize")

//#define PATH_FCOPY (LIBDIR "/firejail/fcopy")
#define PATH_FCOPY (RUN_FIREJAIL_LIB_DIR "/fcopy")

#define SBOX_STDIN_FILE "/run/firejail/mnt/sbox_stdin"

//#define PATH_FLDD (LIBDIR "/firejail/fldd")
#define PATH_FLDD (RUN_FIREJAIL_LIB_DIR "/fldd")

// bitmapped filters for sbox_run
#define SBOX_ROOT (1 << 0)			// run the sandbox as root
#define SBOX_USER (1 << 1)			// run the sandbox as a regular user
#define SBOX_SECCOMP (1 << 2)		// install seccomp
#define SBOX_CAPS_NONE (1 << 3)		// drop all capabilities
#define SBOX_CAPS_NETWORK (1 << 4)	// caps filter for programs running network programs
#define SBOX_ALLOW_STDIN (1 << 5)		// don't close stdin
#define SBOX_STDIN_FROM_FILE (1 << 6)	// open file and redirect it to stdin
#define SBOX_CAPS_HIDEPID (1 << 7)	// hidepid caps filter for running firemon
#define SBOX_CAPS_NET_SERVICE (1 << 8) // caps filter for programs running network services
#define SBOX_KEEP_FDS (1 << 9) // keep file descriptors open
#define FIREJAIL_MAX_FD 20 // getdtablesize() is overkill for a firejail process

// run sbox
int sbox_run(unsigned filter, int num, ...);
int sbox_run_v(unsigned filter, char * const arg[]);
void sbox_exec_v(unsigned filter, char * const arg[]) __attribute__((noreturn));

// run_files.c
void delete_run_files(pid_t pid);
void delete_bandwidth_run_file(pid_t pid);
void set_name_run_file(pid_t pid);
void set_x11_run_file(pid_t pid, int display);
void set_profile_run_file(pid_t pid, const char *fname);

#endif
