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
#include <sys/ptrace.h>
#include <linux/seccomp.h>

int main(int argc, char **argv)
{
	char filename[256];


	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	assert(!prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER_EXTENDED, &prog_fd));
	close(111);
	assert(errno == EBADF);
	close(999);
	assert(errno = EPERM);

	return 0;
}
