#include <uapi/linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/checmate.h>
#include "bpf_helpers.h"
#include <linux/version.h>

struct bpf_map_def SEC("maps") cgroup_map = {
	.type			= BPF_MAP_TYPE_CGROUP_ARRAY,
	.key_size		= sizeof(u32),
	.value_size		= sizeof(u32),
	.max_entries	= 1,
};

SEC("checmate")
int prog(struct checmate_ctx *ctx)
{
	struct sockaddr addr;
	struct sockaddr_in *addr_in;

	int ret;
	if (!bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;
	
	char fmt[] = "Beginning Rewrite: %d\n";
	bpf_trace_printk(fmt, sizeof(fmt), 0);
	
	bpf_probe_read(&addr, sizeof(addr), ctx->socket_bind.address);
	bpf_trace_printk(fmt, sizeof(fmt), addr.sa_family);
	if (addr.sa_family != AF_INET)
		return 0;
	addr_in = (struct sockaddr_in *)&addr;
	bpf_trace_printk(fmt, sizeof(fmt), 0);

	if (be16_to_cpu(addr_in->sin_port) != 2234)
		return 0; 
	bpf_trace_printk(fmt, sizeof(fmt), 0);

	addr_in->sin_port = cpu_to_be16(1234);

	int out = bpf_probe_write_checmate(ctx, ctx->socket_bind.address, &addr, sizeof(*addr_in));
	char outfmt[] = "result: %d\n";

	bpf_trace_printk(outfmt, sizeof(outfmt), out);
	
	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
