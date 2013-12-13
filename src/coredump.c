/*
 * Initiates the core-dump
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2013, 2014
 *
 * Authors:
 *      Janani Venkataraman <jananve@in.ibm.com>
 *      Suzuki K. Poulose <suzuki@in.ibm.com>
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <coredump.h>

/* For logging all the messages */
FILE *fp_log;

/* Status of the dump */
int status;

/* Logging messages */
void gencore_log(char *fmt, ...)
{
	va_list argptr;
	va_start(argptr, fmt);
	vfprintf(fp_log, fmt, argptr);
	va_end(argptr);
}

/* Core process object */
struct core_proc cp;

/* Initialised core process members */
void init_core(void)
{
	memset(&cp, 0, sizeof(struct core_proc));
}

/* Gets the Thread IDS and siezes them */
int seize_threads(int pid)
{
	char filename[40];
	DIR *dir;
	int ct = 0, ret = 0, tmp_tid;
	struct dirent *entry;
	char state;

	ret = get_thread_count(pid);
	if (ret == -1)
		return -1;

	cp.thread_count = ret;
	cp.t_id = calloc(cp.thread_count, sizeof(int));
	if (!cp.t_id) {
		status = errno;
		gencore_log("Could not allocate memory for thread_ids.\n");
		return -1;
	}

	snprintf(filename, 40, "/proc/%d/task", pid);
	dir = opendir(filename);

	while ((entry = readdir(dir))) {
		if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
			tmp_tid = atoi(entry->d_name);
			ret = ptrace(PTRACE_SEIZE, tmp_tid, 0, 0);
			if (ret) {
				state = get_thread_status(tmp_tid);
				if (state == 'Z')
					goto assign;
				status = errno;
				gencore_log("Could not seize thread: %d\n",
								tmp_tid);
				break;
			}
			ret = ptrace(PTRACE_INTERRUPT, tmp_tid, 0, 0);
			if (ret) {
				state = get_thread_status(tmp_tid);
				if (state == 'Z')
					goto assign;
				status = errno;
				gencore_log("Could not interrupt thread: %d\n",
								tmp_tid);
				break;
			}
assign:
			/* If a new thread, is created after we fetch the thread_count,
			 * we may encounter a buffer overflow situation in the cp_tid.
			 * Hence we check this case and re-allocate memory if required.
			 */
			cp.t_id[ct++] = tmp_tid;
		}
	}

	/* Reassigning based on successful seizes */
	cp.thread_count = ct;

	closedir(dir);

	/* Successful seize and interrupt on all threads makes ret = 0 */
	return ret;
}

/* Wait for threads to stop */
int wait_for_threads_to_stop(void)
{
	int i;
	char state;

	/*
	 * We check for the process to stop infinitely now. We need
	 * to break out after some definite time. Need to work on
	 * that.
	 */
	for (i = 0; i < cp.thread_count; i++) {
		do {
			state = get_thread_status(cp.t_id[i]);
			if (state != 't')
				sched_yield();
		} while (state != 't' && state!='Z' && state != -1);
		if (state == -1)
			return -1;
	}

	return 0;
}

/* Release the threads that are held */
int release_threads(void)
{
	int i, ret = 0;
	char state;

	/* Detach the process to be dumped */
	for (i = 0; i < cp.thread_count; i++) {
		state = get_thread_status(cp.t_id[i]);
		if (state == 't') {
			ret += ptrace(PTRACE_DETACH, cp.t_id[i], 0, 0);
			if (ret)
				gencore_log("Could not detach from thread: %d\n",
								cp.t_id[i]);
		}
	}

	/* Successful detach on all threads makes ret = 0 */
	return ret;
}

/* Performs the core dump */
int do_coredump(int pid, char *core_file)
{
	int ret;

	/* Initialise members of core process */
	init_core();

	/* Getting thread information and seizing them */
	ret = seize_threads(pid);
	if (ret)
		goto cleanup;

	/* Wait for threads to stop */
	ret = wait_for_threads_to_stop();
	if (ret)
		goto cleanup;

	/* Get VMAS */
	ret = get_vmas(pid, &cp);
	if (ret)
		goto cleanup;

	/* Compat Support */
	cp.elf_class = ret = get_elf_class(pid, &cp);
	if (ret == -1)
		goto cleanup;

cleanup:

	/* Release the threads */
	release_threads();

	if (cp.t_id)
		free(cp.t_id);

	if (cp.vmas)
		free_maps(cp.vmas);

	errno = status;

	return ret;
}

/* Daemon for self dump */
int daemon_dump(void)
{
	return 0;
}

#if HAVE_SYSTEMD_SOCKET_SUPPORT
/* Systemd socket for self dump */
int socket_dump(void)
{
	return 0;
}
#endif

int main(int argc, char *argv[])
{
	int ret;
	int pid;
	char core_file[15];

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Invalid number of arguments.\n\n");
		fprintf(stderr, "Usage: %s pid [output-file-name]\n", argv[0]);
		return -1;
	}

	if (strcmp(argv[1], "--daemon") == 0)
		ret = daemon_dump();
#if HAVE_SYSTEMD_SOCKET_SUPPORT
	else if (strcmp(argv[1], "--socket") == 0) {
		fp_log = stderr;
		ret = socket_dump();
	}
#endif
	else if (strcmp(argv[1], "--help") == 0) {
		printf("Usage: %s pid [output-file-name]\n", argv[0]);
		return -1;
	} else {
		fp_log = stderr;
		pid = atoi(argv[1]);
		if (pid == 0 && argv[1][0] != '0') {
			fprintf(stderr, "Enter a valid PID.\n");
			fprintf(stderr, "Usage: %s pid [output-file-name]\n", argv[0]);
			return -1;
		}
		if (argc == 2) {
			snprintf(core_file, 15, "core.%d", pid);
			ret = do_coredump(pid, core_file);
		} else
			ret = do_coredump(pid, argv[2]);

		if (ret == -1)
			gencore_log("Failed to create core file.\n");
	}

	return ret;
}
