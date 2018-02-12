// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <linux/bpf.h>
#include <unistd.h>
#include "libbpf.h"
#include "bpf_load.h"
#include <linux/bpf.h>
#include <sys/prctl.h>
#include <strings.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sched.h>

#define PTRACE_SECCOMP_GET_FILTER_EXTENDED	0x420e
static void tracee(void)
{
	assert(!prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));

	assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER_EXTENDED, &prog_fd));
	sched_yield();
	assert(errno == EPERM);
	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	kill(getpid(), SIGSTOP);
}

int main(int argc, char **argv)
{
	struct bpf_prog_info loaded_prog_info = {}, retrieved_prog_info = {};
	char filename[256];
	__u32 info_len;
	pid_t child;
	int fd;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	info_len = sizeof(loaded_prog_info);
	assert(!bpf_obj_get_info_by_fd(prog_fd[0], &loaded_prog_info,
				       &info_len));

	child = fork();
	if (child == 0) {
		tracee();
		return 0;
	}

	wait(NULL);
	/* Fetches eBPF filter from traced child */
	fd = ptrace(PTRACE_SECCOMP_GET_FILTER_EXTENDED, child, 0, NULL);
	kill(child, SIGKILL);
	assert(fd >= 0);
	info_len = sizeof(retrieved_prog_info);
	assert(!bpf_obj_get_info_by_fd(fd, &retrieved_prog_info, &info_len));
	assert(retrieved_prog_info.id == loaded_prog_info.id);

	return 0;
}
