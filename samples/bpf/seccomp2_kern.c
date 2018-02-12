#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/unistd.h>
#include "bpf_helpers.h"
#include <uapi/linux/errno.h>

static inline int unknown(struct seccomp_data *ctx)
{
	if (ctx->args[0] % 2 == 0)
		return SECCOMP_RET_KILL;
	return SECCOMP_RET_LOG;
}

/* Returns errno on sched_yield syscall */
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	if (ctx->nr == __NR_sched_yield)
		return SECCOMP_RET_ERRNO | EPERM;

	return SECCOMP_RET_ALLOW;
}

char _license[] SEC("license") = "aGPL";
