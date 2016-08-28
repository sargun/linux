/* Copyright (c) 2016 Sargun Dhillon <sargun@sargun.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <fcntl.h>
#include <errno.h>
#include <linux/bpf.h>
#include "cgroup_helpers.h"

#define CGROUP_NAME "test_current_task_under"

int main(int argc, char **argv)
{
	char filename[256];
	int cg2, idx = 0;
	pid_t remote_pid, local_pid = getpid();

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (setup_cgroups())
		return 1;

	if (mkdirp(CGROUP_NAME))
		return 1;

	cg2 = open(CGROUP_NAME, O_RDONLY);
	if (cg2 < 0) {
		log_err("opening target cgroup");
		goto cleanup_cgroup_err;
	}

	if (bpf_update_elem(map_fd[0], &idx, &cg2, BPF_ANY)) {
		log_err("Adding target cgroup to map");
		goto cleanup_cgroup_err;
	}
	if (join_cgroup(CGROUP_NAME)) {
		log_err("Leaving target cgroup");
		goto cleanup_cgroup_err;
	}

	/*
	 * The installed helper program catched the sync call, and should
	 * write it to the map.
	 */

	sync();
	bpf_lookup_elem(map_fd[1], &idx, &remote_pid);

	if (local_pid != remote_pid) {
		fprintf(stderr,
			"BPF Helper didn't write correct PID to map, but: %d\n",
			remote_pid);
		goto leave_cgroup_err;
	}

	/* Verify the negative scenario; leave the cgroup */
	if (join_cgroup("."))
		goto leave_cgroup_err;

	remote_pid = 0;
	bpf_update_elem(map_fd[1], &idx, &remote_pid, BPF_ANY);

	sync();
	bpf_lookup_elem(map_fd[1], &idx, &remote_pid);

	if (local_pid == remote_pid) {
		fprintf(stderr, "BPF cgroup negative test did not work\n");
		goto cleanup_cgroup_err;
	}

	rmdir(CGROUP_NAME);
	return 0;

	/* Error condition, cleanup */
leave_cgroup_err:
	join_cgroup(".");
cleanup_cgroup_err:
	rmdir(CGROUP_NAME);
	return 1;
}
