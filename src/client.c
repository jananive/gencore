/*
 * Client interface for selfdump.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2013
 *
 * Authors:
 *      Janani Venkataraman <jananve@in.ibm.com>
 */

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <gencore.h>

int setup_connection(void)
{
	int socket_fd;
	struct sockaddr_un address;
	socklen_t len = sizeof(struct sockaddr_un);

	/* Creating the socket */
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (socket_fd < 0)
		return -1;

	memset(&address, 0, len);

	address.sun_family = PF_FILE;
	strcpy(address.sun_path, SOCKET_PATH);

	/* Connecting to the server */
	if (connect(socket_fd, (struct sockaddr *) &address, len)) {
		close(socket_fd);
		return -1;
	}

	return socket_fd;
}

/* Sends message to client */
int send_core_filename(int socket_fd, char *corefile)
{
	if (write(socket_fd, corefile , strlen(corefile) + 1) == -1)
		return errno;

	return 0;
}

/* Receive message from client */
int receive_reply(int socket_fd)
{
	int reply;

	if (read(socket_fd, &reply , sizeof(reply)) == -1)
		return errno;

	return reply;
}

int dump_request(int socket_fd, char *corefile)
{
	int ret;

	/* Sends request */
	ret = send_core_filename(socket_fd, corefile);
	if (ret)
		goto cleanup;

	/* Receives acknowledgment */
	ret = receive_reply(socket_fd);
	if (ret)
		goto cleanup;

	/* Receives status */
	ret = receive_reply(socket_fd);
	if (ret)
		goto cleanup;

cleanup:
	close(socket_fd);

	return ret;
}

int gencore(char *corefile)
{
	int socket, ret;

	/* Socket operation */
	socket = setup_connection();
	if (socket == -1) {
		ret = errno;
		goto cleanup;
	}

	/* Asks for a self dump */
	ret = dump_request(socket, corefile);
	if (ret)
		goto cleanup;

cleanup:

	return ret;
}
