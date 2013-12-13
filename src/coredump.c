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

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <elf.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <coredump.h>

/* Main Socket */
int socket_fd;

/* Accepted Socket */
int new_sock;

#define CORE_FILE_NAME_SZ 1000	/* Size of core file name */

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

#ifndef GENCORE_DAEMON_LOGFILE
#define GENCORE_DAEMON_LOGFILE "/var/log/gencored.log"
#endif

/* PID of Daemon */
int pid_log;

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

/* Free Notes */
void free_notes(struct mem_note *head)
{
	struct mem_note *tmp;

	while (head) {
		tmp = head->next;
		free(head);
		head = tmp;
	}
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

	/* Initialise core file name */
	cp.corefile = core_file;

	/* Do elf_dump */
	if (cp.elf_class == ELFCLASS32)
		ret = do_elf32_coredump(pid, &cp);
	else
		ret = do_elf64_coredump(pid, &cp);
	if (ret)
		goto cleanup;

cleanup:

	/* Release the threads */
	release_threads();

	if (cp.t_id)
		free(cp.t_id);

	if (cp.vmas)
		free_maps(cp.vmas);

	if (cp.elf_hdr)
		free(cp.elf_hdr);

	if (cp.notes)
		free_notes(cp.notes);

	if (cp.phdrs)
		free(cp.phdrs);

	if (cp.phdrs_count)
		free(cp.shdrs);

	errno = status;

	return ret;
}

/* Creating a Unix socket */
int create_socket(void)
{
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0) {
		gencore_log("[%d]: Could not create a socket:%s.\n",
					pid_log, strerror(errno));
		return -1;
	}

	gencore_log("[%d]: Created socket.\n", pid_log);

	return 0;
}

/* Binding the socket to a address */
int bind_socket(void)
{
	struct sockaddr_un address;
	struct stat buffer;
	if (stat(SOCKET_PATH, &buffer) == 0)
		unlink(SOCKET_PATH);

	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = PF_FILE;
	strcpy(address.sun_path, SOCKET_PATH);

	if (bind(socket_fd, (struct sockaddr *) &address,
			sizeof(struct sockaddr_un)) != 0) {
		gencore_log("[%d]: Could not bind:%s.\n", pid_log,
							strerror(errno));
		close(socket_fd);
		return -1;
	}

	if (chmod(SOCKET_PATH, S_IROTH | S_IWOTH
						| S_IRUSR | S_IWUSR)) {
		gencore_log("[%d]: Could not change permissions of socket:%s.\n",
						pid_log, strerror(errno));
		close(socket_fd);
		return -1;
	}

	gencore_log("[%d]: Bind done.\n", pid_log);

	return 0;
}

/* Listen for connections */
int listen_conn(void)
{
	if (listen(socket_fd, 5) != 0) {
		gencore_log("[%d]: Could not listen:%s.\n", pid_log,
							strerror(errno));
		close(socket_fd);
		return -1;
	}

	gencore_log("[%d]: Listening.\n", pid_log);

	return 0;
}

/* Setting up server */
int setup_server(void)
{
	int ret;

	/* Create Socket */
	ret = create_socket();
	if (ret)
		return -1;

	/* Bind Socket */
	ret = bind_socket();
	if (ret)
		return -1;

	/* Listen for connections */
	ret = listen_conn();
	if (ret)
		return -1;

	return 0;
}

/* Blocking on a request */
int block_on_request(void)
{
	fd_set read;

	do {
		/* Initialise */
		FD_ZERO(&read);
		FD_SET(socket_fd, &read);

		gencore_log("[%d]: Waiting on incoming request.\n", pid_log);

		if (select(socket_fd + 1, &read, NULL, NULL, NULL) <= 0) {
			/*
			 * EINTR just means a signal is caught and hence, we need not
			 * terminate for this error.
			 */
			if (errno != EINTR) {
				gencore_log("[%d]: Error while waiting for connection requests.\n",
						pid_log, strerror(errno));
				close(socket_fd);
				return -1;
			}
		}

	} while(FD_ISSET(socket_fd, &read) == 0);

	gencore_log("[%d]: Request found.\n", pid_log);

	return 0;
}

/* Handles a SIGCHILD */
void sigchild_handler(int sig)
{
	int pid;

	pid = waitpid(0, &status, WNOHANG);

	gencore_log("[%d]: Request handled by child with PID:%d and exited.\n",
				pid_log, pid);
}

/* Sends message to client */
int send_reply(int err)
{
	if (write(new_sock, &err , sizeof(err)) == -1) {
		gencore_log("[%d]: Could not send message:%s\n",
					pid_log, strerror(errno));
		return -1;
	}

	gencore_log("[%d]: Message sent:%d\n", pid_log, err);

	return 0;
}

/* Receive message from client */
int receive_core_filename(char *core_file)
{
	memset(core_file, 0, CORE_FILE_NAME_SZ);
	if (read(new_sock, core_file , CORE_FILE_NAME_SZ) == -1) {
		send_reply(errno);
		gencore_log("[%d]: Could not get Core file name:%s\n",
					pid_log, strerror(errno));
		return -1;
	}

	gencore_log("[%d]: Core file path received:%s\n", pid_log,
						core_file);
	/* Sending the acknowledgment */
	send_reply(0);

	return 0;
}

/* Get client details */
int get_client_pid(struct ucred *client_info)
{
	socklen_t len = sizeof(struct ucred);
	if (getsockopt(new_sock, SOL_SOCKET, SO_PEERCRED,
				client_info, &len)) {
		send_reply(errno);
		gencore_log("[%d]: Can't get credentials of the client:%s\n",
				pid_log, strerror(errno));
		return -1;
	}

	return 0;
}

/* Dumps the client process */
int dump_task(struct ucred *client_info, char *core_file)
{

	char filename[40], cwd[CORE_FILE_NAME_SZ], corefile[CORE_FILE_NAME_SZ];
	memset(filename, 0, 40);
	memset(cwd, 0, CORE_FILE_NAME_SZ);
	memset(corefile, 0, CORE_FILE_NAME_SZ);

	if (setgid(client_info->gid)) {
		send_reply(errno);
		gencore_log("[%d]: Could not change GID:%s\n",
				pid_log, strerror(errno));
		return -1;
	}

	if (setuid(client_info->uid)) {
		send_reply(errno);
		gencore_log("[%d]: Could not change UID:%s\n",
				pid_log, strerror(errno));
		return -1;
	}

	/* Checking if UID was changed */
	if (geteuid() != client_info->uid) {
		send_reply(errno);
		gencore_log("[%d]: Could not change UID:%s\n",
				pid_log, strerror(errno));
		return -1;
	}

	/* Converting the path to absolute path */
	if (core_file[0] != '/') {
		snprintf(filename, 40, "/proc/%d/cwd", client_info->pid);
		readlink(filename, cwd, CORE_FILE_NAME_SZ);
		snprintf(corefile, CORE_FILE_NAME_SZ, "%s/%s", cwd, core_file);
	} else
		strcpy(corefile, core_file);

	if (do_coredump(client_info->pid, (char *)corefile)) {
		send_reply(errno);
		gencore_log("[%d]: Could not create core file %s.\n",
						pid_log, corefile);
		fflush(fp_log);
		return -1;
	}

	gencore_log("[%d]: Core file %s created.\n", pid_log,
							corefile);

	send_reply(0);

	return 0;
}

/* Services requests */
int service_request(void)
{
	int ret;
	char core_file[CORE_FILE_NAME_SZ];
	struct ucred client_info;

	/* Receive the message */
	ret = receive_core_filename(core_file);
	if (ret)
		goto cleanup;

	/* Fetch client PID */
	ret = get_client_pid(&client_info);
	if (ret)
		goto cleanup;

	/* Dump process */
	ret = dump_task(&client_info, core_file);
	if (ret)
		goto cleanup;

cleanup:
	close(new_sock);
	if (ret == -1)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

/* Handles new requests */
int handle_request(void)
{
	int pid_new;
	struct sockaddr_un client_address;
	socklen_t client_size = sizeof(client_address);

	new_sock = accept(socket_fd, (struct sockaddr *) &client_address,
							&client_size);
	if (new_sock < 0) {
		gencore_log("[%d]: Could not accept:%s\n", pid_log,
							strerror(errno));
		close(socket_fd);
		fclose(fp_log);
		return -1;
	}

	gencore_log("[%d]: Accepted.\n", pid_log);

	gencore_log("[%d]: Handling request.\n", pid_log);

	/* New thread to service request */
	pid_new = fork();
	if (pid_new == 0) {
		pid_log = getpid();
		service_request();
	}

	return 0;
}

/* Daemon for self dump */
int daemon_dump(void)
{
	int ret;

	/* Check if daemon is running as root */
	if (geteuid()) {
		fprintf(stderr, "Run the daemon as root.\n");
		return -1;
	}

	/* Daemonizing it */
	if (daemon(0, 0)) {
		fprintf(stderr, "Daemon not up %s.", strerror(errno));
		return -1;
	}

	/* Get the PID of the daemon */
	pid_log = getpid();

	fp_log = fopen(GENCORE_DAEMON_LOGFILE, "w+");
	if (fp_log == NULL) {
		openlog("gencore_daemon_log", LOG_PID|LOG_CONS, LOG_USER);
		syslog(LOG_DAEMON, "Could not open: %s.\n",
					GENCORE_DAEMON_LOGFILE);
		closelog();
		return -1;
	}

	/* Setting up server */
	ret = setup_server();
	if (ret)
		goto cleanup;

	/* Flush the log */
	fflush(fp_log);

	/* SIGCHILD - Signal handler */
	signal(SIGCHLD, sigchild_handler);

	while (1) {

		/* Blocks on request */
		ret = block_on_request();
		if (ret)
			goto cleanup;

		/* Flush the log */
		fflush(fp_log);

		/* Handle new connections */
		ret = handle_request();
		if (ret)
			goto cleanup;

		/* Flush the log */
		fflush(fp_log);
	}

	return 0;

cleanup:

	fclose(fp_log);

	if (ret == -1)
		return -1;

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
		else
			fprintf(stdout, "Created core file.\n");
	}

	return ret;
}
