/* Copyright (c) 2016 Sargun Dhillon <sargun@sargun.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "bpf_load.h"
#include "libbpf.h"
#include <netinet/in.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "cgroup_helpers.h"

#define CONN_LIMIT		10
#define CGROUP_NAME		"limit_connections"
#define CONTROL_FILE_CONNECT	"limit_connections/checmate.socket_connect"
#define CONTROL_FILE_SK_FREE	"limit_connections/checmate.sk_free_security"

int main(int ac, char **argv)
{
	int i, sock, connect_fd, sk_free_fd, rc = 0;
	struct sockaddr_in addr;
	int socks[CONN_LIMIT];
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	if (!(prog_fd[0] && prog_fd[1])) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	if (setup_cgroups())
		return 1;

	if (add_controller("checmate"))
		return 1;

	if (mkdirp(CGROUP_NAME))
		return 1;

	if (join_cgroup(CGROUP_NAME)) {
		log_err("Joining target group");
		rc = 1;
		goto leave_cgroup_err;
	}

	connect_fd = open(CONTROL_FILE_CONNECT, O_WRONLY);
	sk_free_fd = open(CONTROL_FILE_SK_FREE, O_WRONLY);

	if (connect_fd < 0 || sk_free_fd < 0) {
		log_err("Unable to open checmate control file");
		rc = 1;
		goto leave_cgroup_err;
	}

	if (reset_bpf_hook(connect_fd))
		goto leave_cgroup_err;
	if (reset_bpf_hook(sk_free_fd))
		goto leave_cgroup_err;

	/* Install the programs */
	assert(dprintf(connect_fd, "%d\n", prog_fd[0]) > 0);
	assert(dprintf(sk_free_fd, "%d\n", prog_fd[1]) > 0);

	addr.sin_family = AF_INET;
	addr.sin_port = htons(1234);

	/* Assigned as "TEST-NET" for use in documentation and examples */
	addr.sin_addr.s_addr = inet_addr("192.0.2.0");

	/* Create connections, and make sure they work */
	for (i = 0; i < CONN_LIMIT; i++) {
		socks[i] = socket(AF_INET, SOCK_DGRAM, 0);
		assert(!connect(socks[i], (struct sockaddr *)&addr,
				sizeof(addr)));
	}

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	/* This last connection should fail, but succeed later */
	assert(connect(sock, (struct sockaddr *)&addr, sizeof(addr)));

	/* Test is socket freeing works correctly */
	for (i = 0; i < CONN_LIMIT; i++)
		close(socks[i]);

	/* Sockets are freed asynchronously, so we need to wait a moment */
	usleep(100000);

	/* Retry the connection with the same sk -- should succeed */
	assert(!connect(sock, (struct sockaddr *)&addr, sizeof(addr)));

	reset_bpf_hook(connect_fd);
	reset_bpf_hook(sk_free_fd);
	close(connect_fd);
	close(sk_free_fd);

leave_cgroup_err:
	join_cgroup(".");
	rmdir(CGROUP_NAME);
	return rc;
}
