#ifndef __CGROUP_HELPERS_H
#define __CGROUP_HELPERS_H
#include <string.h>

#define clean_errno() (errno == 0 ? "None" : strerror(errno))
#define log_err(MSG, ...) fprintf(stderr, "(%s:%d: errno: %s) " MSG "\n", \
	__FILE__, __LINE__, clean_errno(), ##__VA_ARGS__)

int mkdirp(char *path);
int setup_cgroups(void);
int join_cgroup(char *path);
int reset_bpf_hook(int fd);
int add_controller(char *controller);

#endif
