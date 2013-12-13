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

/* Performs the core dump */
int do_coredump(int pid, char *core_file)
{
	return 0;
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
