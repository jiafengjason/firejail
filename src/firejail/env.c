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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

typedef struct env_t {
	struct env_t *next;
	char *name;
	char *value;
	ENV_OP op;
} Env;
static Env *envlist = NULL;

static void env_add(Env *env) {
	env->next = NULL;

	// add the new entry at the end of the list
	if (envlist == NULL) {
		envlist = env;
		return;
	}

	Env *ptr = envlist;
	while (1) {
		if (ptr->next == NULL) {
			ptr->next = env;
			break;
		}
		ptr = ptr->next;
	}
}

// default sandbox env variables
void env_defaults(void) {
	// Qt fixes
	if (setenv("QT_X11_NO_MITSHM", "1", 1) < 0)
		errExit("setenv");
	if (setenv("QML_DISABLE_DISK_CACHE", "1", 1) < 0)
		errExit("setenv");
	if (setenv("container", "firejail", 1) < 0) // LXC sets container=lxc,
		errExit("setenv");
	if (!cfg.shell)
		cfg.shell = guess_shell();
	if (cfg.shell && setenv("SHELL", cfg.shell, 1) < 0)
		errExit("setenv");

	// spawn KIO slaves inside the sandbox
	if (setenv("KDE_FORK_SLAVES", "1", 1) < 0)
		errExit("setenv");

	// set prompt color to green
	int set_prompt = 0;
	if (checkcfg(CFG_FIREJAIL_PROMPT))
		set_prompt = 1;
	else { // check FIREJAIL_PROMPT="yes" environment variable
		char *prompt = getenv("FIREJAIL_PROMPT");
		if (prompt && strcmp(prompt, "yes") == 0)
			set_prompt = 1;
	}

	if (set_prompt) {
		//export PS1='\[\e[1;32m\][\u@\h \W]\$\[\e[0m\] '
		if (setenv("PROMPT_COMMAND", "export PS1=\"\\[\\e[1;32m\\][\\u@\\h \\W]\\$\\[\\e[0m\\] \"", 1) < 0)
			errExit("setenv");
	}
	else {
		// remove PROMPT_COMMAND
		if (setenv("PROMPT_COMMAND", ":", 1) < 0) // unsetenv() will not work here, bash still picks it up from somewhere
			errExit("setenv");
	}

	// set the window title
	if (!arg_quiet && isatty(STDOUT_FILENO))
		printf("\033]0;firejail %s\007", cfg.window_title);

	// pass --quiet as an environment variable, in case the command calls further firejailed commands
	if (arg_quiet)
		setenv("FIREJAIL_QUIET", "yes", 1);

	fflush(0);
}

// parse and store the environment setting
void env_store(const char *str, ENV_OP op) {
	EUID_ASSERT();
	assert(str);

	// some basic checking
	if (*str == '\0')
		goto errexit;
	char *ptr = strchr(str, '=');
	if (op == SETENV) {
		if (!ptr)
			goto errexit;
		ptr++;
		if (*ptr == '\0')
			goto errexit;
	}

	// build list entry
	Env *env = malloc(sizeof(Env));
	if (!env)
		errExit("malloc");
	memset(env, 0, sizeof(Env));
	env->name = strdup(str);
	if (env->name == NULL)
		errExit("strdup");
	if (op == SETENV) {
		char *ptr2 = strchr(env->name, '=');
		assert(ptr2);
		*ptr2 = '\0';
		env->value = ptr2 + 1;
	}
	env->op = op;

	// add entry to the list
	env_add(env);
	return;

errexit:
	fprintf(stderr, "Error: invalid --env setting\n");
	exit(1);
}

// set env variables in the new sandbox process
void env_apply(void) {
	Env *env = envlist;

	while (env) {
		if (env->op == SETENV) {
			if (setenv(env->name, env->value, 1) < 0)
				errExit("setenv");
		}
		else if (env->op == RMENV) {
			unsetenv(env->name);
		}
		env = env->next;
	}
}
