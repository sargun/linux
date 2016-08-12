#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "cgroup_helpers.h"

#define CGROUP_MOUNT_PATH "/mnt"

int add_controller(char *controller)
{
	int fd, rc = 0;

	fd = open("cgroup.subtree_control", O_WRONLY);
	if (fd < 0) {
		log_err("Unable to open subtree_control");
		return 1;
	}
	if (dprintf(fd, "+%s\n", controller) < 0) {
		log_err("Adding Controller");
		rc = 1;
	}
	close(fd);
	return rc;
}
int mkdirp(char *path)
{
	int rc;

	rc = mkdir(path, 0777);
	if (rc && errno == EEXIST)
		return 0;
	return rc;
}

/*
 * This is to avoid interfering with existing cgroups. Unfortunately,
 * most people don't have cgroupv2 enabled at this point in time.
 * It's easier to create our own mount namespace and manage it
 * ourselves. This function drops you into the top of that cgroup2
 * mount point, so make sure you call load_bpf before calling this.
 */
int setup_cgroups(void)
{
	if (unshare(CLONE_NEWNS)) {
		log_err("unshare");
		return 1;
	}

	if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
		log_err("mount fakeroot");
		return 1;
	}

	if (mount("none", CGROUP_MOUNT_PATH, "cgroup2", 0, NULL)) {
		log_err("mount cgroup2");
		return 1;
	}

	if (chdir(CGROUP_MOUNT_PATH)) {
		log_err("chdir");
	}

	return 0;
}
int join_cgroup(char *path)
{
	char cgroup_path[1024];
	pid_t pid = getpid();
	int fd, rc = 0;

	snprintf(cgroup_path, sizeof(cgroup_path), "%s/cgroup.procs", path);

	fd = open(cgroup_path, O_WRONLY);
	if (fd < 0) {
		log_err("Opening Cgroup");
		return 1;
	}

	if (dprintf(fd, "%d\n", pid) < 0) {
		log_err("Joining Cgroup");
		rc = 1;
	}
	close(fd);
	return rc;
}

int reset_bpf_hook(int fd)
{
	if (dprintf(fd, "0\n") < 0) {
		log_err("Unable to reset BPF hook");
		return 1;
	}
	return 0;
}