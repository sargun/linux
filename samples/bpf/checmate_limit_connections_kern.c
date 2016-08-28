/* Copyright (c) 2016 Sargun Dhillon <sargun@sargun.me>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program limits the usage of sockets connecting to a given ip:port.
 * At the moment it doesn't take protocol (SOCK_STREAM vs. SOCK_DGRAM) into
 * account, but doing so would just involve reading some more fields.
 *
 * Since proper refcnting would be fairly hard in eBPF, we do probablistic
 * refcnting. This means you're probablistically limited to 10 connections.
 * You may get fewer, but you'll never get more than 10.
 *
 * We hash the ip + port with fnv1a into a 22-bit space, and keep track of the
 * connection count. We also keep track of the dstaddr of a given socket in
 * another map as we already have to keep track of the sockets that qualified
 * themselves for tracking (those connecting to AF_INET in this case). We
 * could track less metadata, but this is an example.
 */

#include <uapi/linux/bpf.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/checmate.h>
#include "bpf_helpers.h"
#include <linux/version.h>
#include <linux/net.h>

#define HASH_BITS	22 /* 2**22 * 4 = 16777216 (16mb) */
#define MASK		(((u32)1 << HASH_BITS) - 1)
#define FNV1_32_INIT	2166136261
#define FNV1_32_PRIME	16777619
#define CONN_LIMIT	10

struct bpf_map_def SEC("maps") sk_to_hash_map = {
	.type			= BPF_MAP_TYPE_HASH,
	.key_size		= sizeof(struct sock *),
	.value_size		= sizeof(u32),
	/* This only allows 16384 socket connections */
	.max_entries		= 16384,
};

struct bpf_map_def SEC("maps") addr_refcnt = {
	.type			= BPF_MAP_TYPE_ARRAY,
	.key_size		= sizeof(int),
	.value_size		= sizeof(u32),
	.max_entries		= 1 << HASH_BITS,
};

static inline u32 fnv1a(struct sockaddr_in *addr)
{
	/*
	 * The reason to take this approach, rather than hash the whole
	 * structure is to avoid accidentally hashing the padding.
	 * The reasoning to start at byte 2 is to skip sin_family,
	 * and to stop at byte 8, because that's where sin_addr + sin_port end.
	 */
	u32 hash = FNV1_32_INIT;
	u8 *data = (u8 *)addr;

	hash = hash ^ (data[2] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = hash ^ (data[3] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = hash ^ (data[4] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = hash ^ (data[5] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = hash ^ (data[6] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = hash ^ (data[7] & 0xff);
	hash = hash * FNV1_32_PRIME;
	hash = (hash >> HASH_BITS) ^ (hash & MASK);

	return hash;
}

SEC("checmate/connect")
int prog_connect(struct checmate_ctx *ctx)
{
	struct sockaddr_in addr_in = {};
	struct sock *sk = 0;
	int rc = 0;
	u32 *refcnt;
	u32 hash;

	rc = bpf_probe_read(&addr_in, sizeof(addr_in),
			    ctx->socket_connect.address);
	if (rc)
		return rc;

	if (addr_in.sin_family != AF_INET)
		return 0;

	rc = bpf_probe_read(&sk, sizeof(sk), &ctx->socket_connect.sock->sk);
	if (rc)
		return rc;

	hash = fnv1a(&addr_in);

	refcnt = bpf_map_lookup_elem(&addr_refcnt, &hash);
	if (!refcnt)
		return -EINVAL;

	if (*refcnt >= CONN_LIMIT)
		return -EUSERS;

	/* The only error we should get at this point is out of space */
	rc = bpf_map_update_elem(&sk_to_hash_map, &sk, &hash, BPF_ANY);
	if (rc)
		return rc;

	__sync_fetch_and_add(refcnt, 1);
	return 0;
}

SEC("checmate/sk_free")
int prog_sk_free(struct checmate_ctx *ctx)
{
	struct sock *sk = ctx->sk_free_security.sk;
	struct sockaddr_in *addr;
	u32 *refcnt, *hash;
	/*
	 * You cannot reuse map values as map keys, therefore we need to copy
	 * the hash to the stack.
	 */
	u32 hash_as_key;

	hash = bpf_map_lookup_elem(&sk_to_hash_map, &sk);
	if (!hash)
		return 0;

	memcpy(&hash_as_key, hash, sizeof(hash_as_key));
	refcnt = bpf_map_lookup_elem(&addr_refcnt, &hash_as_key);
	if (!refcnt)
		return -EINVAL;

	__sync_fetch_and_add(refcnt, -1);
	bpf_map_delete_elem(&sk_to_hash_map, &sk);

	return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
