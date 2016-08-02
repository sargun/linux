/*
 * Checmate Linux Security Module
 *
 * Copyright (C) 2016 Sargun Dhillon <sargun@sargun.me>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation.
 *
 */

#include <linux/bpf.h>
#include <linux/checmate.h>

static const struct bpf_func_proto *checmate_prog_func_proto(enum bpf_func_id func_id)
{
	switch (func_id) {
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_probe_read:
		return &bpf_probe_read_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_get_current_pid_tgid:
		return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_task:
		return &bpf_get_current_task_proto;
	case BPF_FUNC_get_current_uid_gid:
		return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_comm:
		return &bpf_get_current_comm_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return NULL;
	}
}

static bool checmate_prog_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  enum bpf_reg_type *reg_type)
{
	if (type != BPF_READ)
		return false;
	if (off < 0 || off >= sizeof(struct checmate_ctx))
		return false;
	return true;
}

static const struct bpf_verifier_ops checmate_prog_ops = {
	.get_func_proto		= checmate_prog_func_proto,
	.is_valid_access	= checmate_prog_is_valid_access,
};

static struct bpf_prog_type_list checmate_tl = {
	.ops	= &checmate_prog_ops,
	.type	= BPF_PROG_TYPE_CHECMATE,
};

void register_checmate_prog_ops(void)
{
	bpf_register_prog_type(&checmate_tl);
}
