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
#include "cgroup_helpers.h"

#define CGROUP_NAME 	"remap_bind_user"
#define CONTROL_FILE	"remap_bind_user/checmate.socket_bind"

int main(int ac, char **argv)
{
	struct sockaddr_in addr = {};
	socklen_t len = sizeof(addr);
	int sock, fd, rc = 0;
	char filename[256];

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}
	if (!prog_fd[0]) {
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

	fd = open(CONTROL_FILE, O_WRONLY);

	if (fd < 0) {
		log_err("Unable to open checmate control file");
		rc = 1;
		goto leave_cgroup_err;
	}

	if (reset_bpf_hook(fd))
		goto leave_cgroup_err;

	/* Install program */
	assert(dprintf(fd, "%d\n", prog_fd[0]) > 0);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		log_err("Creating socket");
		rc = 1;
		goto cleanup_hook_err;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(6789);
	assert(bind(sock, (const struct sockaddr *)&addr, sizeof(addr)) == 0);
	assert(getsockname(sock, (struct sockaddr *)&addr, &len) == 0);
	assert(addr.sin_port == htons(12345));


cleanup_hook_err:
	reset_bpf_hook(fd);
	close(fd);
leave_cgroup_err:
	join_cgroup(".");
	rmdir(CGROUP_NAME);
	return rc;
}
