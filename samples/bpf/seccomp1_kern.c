#include <uapi/linux/seccomp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/unistd.h>
#include "bpf_helpers.h"
#include <uapi/linux/errno.h>

/* Returns EPERM when trying to close fd 999 */
SEC("seccomp")
int bpf_prog1(struct seccomp_data *ctx)
{
	if (ctx->nr == __NR_close && ctx->args[0] == 999)
		return SECCOMP_RET_ERRNO | EPERM;

	return SECCOMP_RET_ALLOW;
}

char _license[] SEC("license") = "GPL";
