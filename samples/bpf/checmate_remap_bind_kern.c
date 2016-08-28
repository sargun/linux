#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/checmate.h>
#include "bpf_helpers.h"

SEC("checmate/prog1")
int prog1(struct checmate_ctx *ctx)
{
	struct sockaddr address = {};
	struct sockaddr_in *in_addr = (struct sockaddr_in *) &address;

	bpf_probe_read(&address, sizeof(struct sockaddr_in),
		       ctx->socket_bind.address);

	if (address.sa_family == AF_INET &&
	    be16_to_cpu(in_addr->sin_port) == 6789) {
		in_addr->sin_port = cpu_to_be16(12345);
		bpf_probe_write_checmate(ctx, ctx->socket_bind.address,
					 in_addr, sizeof(*in_addr));
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
