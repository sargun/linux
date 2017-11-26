// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/srcu.h>
#include <linux/list.h>
#include <linux/jump_label.h>
#include <linux/module.h>

#include "dynamic.h"

static DEFINE_MUTEX(dynamic_hook_lock);
DEFINE_STATIC_KEY_ARRAY_FALSE(dynamic_hooks_keys, __MAX_DYNAMIC_SECURITY_HOOK);

#define DYNAMIC_HOOK(FUNC) \
[DYNAMIC_SECURITY_HOOK_##FUNC] = {					\
	.name		= #FUNC,					\
}


struct dynamic_hook dynamic_hooks[__MAX_DYNAMIC_SECURITY_HOOK] = {
	DYNAMIC_HOOK(binder_set_context_mgr),
	DYNAMIC_HOOK(binder_transaction),
	DYNAMIC_HOOK(binder_transfer_binder),
	DYNAMIC_HOOK(binder_transfer_file),
	DYNAMIC_HOOK(ptrace_access_check),
	DYNAMIC_HOOK(ptrace_traceme),
	DYNAMIC_HOOK(capget),
	DYNAMIC_HOOK(capset),
	DYNAMIC_HOOK(capable),
	DYNAMIC_HOOK(quotactl),
	DYNAMIC_HOOK(quota_on),
	DYNAMIC_HOOK(syslog),
	DYNAMIC_HOOK(settime),
	DYNAMIC_HOOK(vm_enough_memory),
	DYNAMIC_HOOK(bprm_set_creds),
	DYNAMIC_HOOK(bprm_check_security),
	DYNAMIC_HOOK(bprm_committing_creds),
	DYNAMIC_HOOK(bprm_committed_creds),
	DYNAMIC_HOOK(sb_alloc_security),
	DYNAMIC_HOOK(sb_free_security),
	DYNAMIC_HOOK(sb_copy_data),
	DYNAMIC_HOOK(sb_remount),
	DYNAMIC_HOOK(sb_kern_mount),
	DYNAMIC_HOOK(sb_show_options),
	DYNAMIC_HOOK(sb_statfs),
	DYNAMIC_HOOK(sb_mount),
	DYNAMIC_HOOK(sb_umount),
	DYNAMIC_HOOK(sb_pivotroot),
	DYNAMIC_HOOK(sb_set_mnt_opts),
	DYNAMIC_HOOK(sb_clone_mnt_opts),
	DYNAMIC_HOOK(sb_parse_opts_str),
	DYNAMIC_HOOK(dentry_init_security),
	DYNAMIC_HOOK(dentry_create_files_as),
#ifdef CONFIG_SECURITY_PATH
	DYNAMIC_HOOK(path_unlink),
	DYNAMIC_HOOK(path_mkdir),
	DYNAMIC_HOOK(path_rmdir),
	DYNAMIC_HOOK(path_mknod),
	DYNAMIC_HOOK(path_truncate),
	DYNAMIC_HOOK(path_symlink),
	DYNAMIC_HOOK(path_link),
	DYNAMIC_HOOK(path_rename),
	DYNAMIC_HOOK(path_chmod),
	DYNAMIC_HOOK(path_chown),
	DYNAMIC_HOOK(path_chroot),
#endif
	DYNAMIC_HOOK(inode_alloc_security),
	DYNAMIC_HOOK(inode_free_security),
	DYNAMIC_HOOK(inode_init_security),
	DYNAMIC_HOOK(inode_create),
	DYNAMIC_HOOK(inode_link),
	DYNAMIC_HOOK(inode_unlink),
	DYNAMIC_HOOK(inode_symlink),
	DYNAMIC_HOOK(inode_mkdir),
	DYNAMIC_HOOK(inode_rmdir),
	DYNAMIC_HOOK(inode_mknod),
	DYNAMIC_HOOK(inode_rename),
	DYNAMIC_HOOK(inode_readlink),
	DYNAMIC_HOOK(inode_follow_link),
	DYNAMIC_HOOK(inode_permission),
	DYNAMIC_HOOK(inode_setattr),
	DYNAMIC_HOOK(inode_getattr),
	DYNAMIC_HOOK(inode_setxattr),
	DYNAMIC_HOOK(inode_post_setxattr),
	DYNAMIC_HOOK(inode_getxattr),
	DYNAMIC_HOOK(inode_listxattr),
	DYNAMIC_HOOK(inode_removexattr),
	DYNAMIC_HOOK(inode_need_killpriv),
	DYNAMIC_HOOK(inode_killpriv),
	DYNAMIC_HOOK(inode_listsecurity),
	DYNAMIC_HOOK(inode_getsecid),
	DYNAMIC_HOOK(inode_copy_up),
	DYNAMIC_HOOK(inode_copy_up_xattr),
	DYNAMIC_HOOK(file_permission),
	DYNAMIC_HOOK(file_alloc_security),
	DYNAMIC_HOOK(file_free_security),
	DYNAMIC_HOOK(file_ioctl),
	DYNAMIC_HOOK(mmap_addr),
	DYNAMIC_HOOK(mmap_file),
	DYNAMIC_HOOK(file_mprotect),
	DYNAMIC_HOOK(file_lock),
	DYNAMIC_HOOK(file_fcntl),
	DYNAMIC_HOOK(file_set_fowner),
	DYNAMIC_HOOK(file_send_sigiotask),
	DYNAMIC_HOOK(file_receive),
	DYNAMIC_HOOK(file_open),
	DYNAMIC_HOOK(task_alloc),
	DYNAMIC_HOOK(task_free),
	DYNAMIC_HOOK(cred_alloc_blank),
	DYNAMIC_HOOK(cred_free),
	DYNAMIC_HOOK(cred_prepare),
	DYNAMIC_HOOK(cred_transfer),
	DYNAMIC_HOOK(kernel_act_as),
	DYNAMIC_HOOK(kernel_create_files_as),
	DYNAMIC_HOOK(kernel_read_file),
	DYNAMIC_HOOK(kernel_post_read_file),
	DYNAMIC_HOOK(kernel_module_request),
	DYNAMIC_HOOK(task_fix_setuid),
	DYNAMIC_HOOK(task_setpgid),
	DYNAMIC_HOOK(task_getpgid),
	DYNAMIC_HOOK(task_getsid),
	DYNAMIC_HOOK(task_getsecid),
	DYNAMIC_HOOK(task_setnice),
	DYNAMIC_HOOK(task_setioprio),
	DYNAMIC_HOOK(task_getioprio),
	DYNAMIC_HOOK(task_prlimit),
	DYNAMIC_HOOK(task_setrlimit),
	DYNAMIC_HOOK(task_setscheduler),
	DYNAMIC_HOOK(task_getscheduler),
	DYNAMIC_HOOK(task_movememory),
	DYNAMIC_HOOK(task_kill),
	DYNAMIC_HOOK(task_prctl),
	DYNAMIC_HOOK(task_to_inode),
	DYNAMIC_HOOK(ipc_permission),
	DYNAMIC_HOOK(ipc_getsecid),
	DYNAMIC_HOOK(msg_msg_alloc_security),
	DYNAMIC_HOOK(msg_msg_free_security),
	DYNAMIC_HOOK(msg_queue_alloc_security),
	DYNAMIC_HOOK(msg_queue_free_security),
	DYNAMIC_HOOK(msg_queue_associate),
	DYNAMIC_HOOK(msg_queue_msgctl),
	DYNAMIC_HOOK(msg_queue_msgsnd),
	DYNAMIC_HOOK(msg_queue_msgrcv),
	DYNAMIC_HOOK(shm_alloc_security),
	DYNAMIC_HOOK(shm_free_security),
	DYNAMIC_HOOK(shm_associate),
	DYNAMIC_HOOK(shm_shmctl),
	DYNAMIC_HOOK(shm_shmat),
	DYNAMIC_HOOK(sem_alloc_security),
	DYNAMIC_HOOK(sem_free_security),
	DYNAMIC_HOOK(sem_associate),
	DYNAMIC_HOOK(sem_semctl),
	DYNAMIC_HOOK(sem_semop),
	DYNAMIC_HOOK(netlink_send),
	DYNAMIC_HOOK(d_instantiate),
	DYNAMIC_HOOK(getprocattr),
	DYNAMIC_HOOK(setprocattr),
	DYNAMIC_HOOK(ismaclabel),
	DYNAMIC_HOOK(secid_to_secctx),
	DYNAMIC_HOOK(secctx_to_secid),
	DYNAMIC_HOOK(release_secctx),
	DYNAMIC_HOOK(inode_invalidate_secctx),
	DYNAMIC_HOOK(inode_notifysecctx),
	DYNAMIC_HOOK(inode_setsecctx),
	DYNAMIC_HOOK(inode_getsecctx),
#ifdef CONFIG_SECURITY_NETWORK
	DYNAMIC_HOOK(unix_stream_connect),
	DYNAMIC_HOOK(unix_may_send),
	DYNAMIC_HOOK(socket_create),
	DYNAMIC_HOOK(socket_post_create),
	DYNAMIC_HOOK(socket_bind),
	DYNAMIC_HOOK(socket_connect),
	DYNAMIC_HOOK(socket_listen),
	DYNAMIC_HOOK(socket_accept),
	DYNAMIC_HOOK(socket_sendmsg),
	DYNAMIC_HOOK(socket_recvmsg),
	DYNAMIC_HOOK(socket_getsockname),
	DYNAMIC_HOOK(socket_getpeername),
	DYNAMIC_HOOK(socket_getsockopt),
	DYNAMIC_HOOK(socket_setsockopt),
	DYNAMIC_HOOK(socket_shutdown),
	DYNAMIC_HOOK(socket_sock_rcv_skb),
	DYNAMIC_HOOK(socket_getpeersec_stream),
	DYNAMIC_HOOK(socket_getpeersec_dgram),
	DYNAMIC_HOOK(sk_alloc_security),
	DYNAMIC_HOOK(sk_free_security),
	DYNAMIC_HOOK(sk_clone_security),
	DYNAMIC_HOOK(sk_getsecid),
	DYNAMIC_HOOK(sock_graft),
	DYNAMIC_HOOK(inet_conn_request),
	DYNAMIC_HOOK(inet_csk_clone),
	DYNAMIC_HOOK(inet_conn_established),
	DYNAMIC_HOOK(secmark_relabel_packet),
	DYNAMIC_HOOK(secmark_refcount_inc),
	DYNAMIC_HOOK(secmark_refcount_dec),
	DYNAMIC_HOOK(req_classify_flow),
	DYNAMIC_HOOK(tun_dev_alloc_security),
	DYNAMIC_HOOK(tun_dev_free_security),
	DYNAMIC_HOOK(tun_dev_create),
	DYNAMIC_HOOK(tun_dev_attach_queue),
	DYNAMIC_HOOK(tun_dev_attach),
	DYNAMIC_HOOK(tun_dev_open),
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_INFINIBAND
	DYNAMIC_HOOK(ib_pkey_access),
	DYNAMIC_HOOK(ib_endport_manage_subnet),
	DYNAMIC_HOOK(ib_alloc_security),
	DYNAMIC_HOOK(ib_free_security),
#endif	/* CONFIG_SECURITY_INFINIBAND */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	DYNAMIC_HOOK(xfrm_policy_alloc_security),
	DYNAMIC_HOOK(xfrm_policy_clone_security),
	DYNAMIC_HOOK(xfrm_policy_free_security),
	DYNAMIC_HOOK(xfrm_policy_delete_security),
	DYNAMIC_HOOK(xfrm_state_alloc),
	DYNAMIC_HOOK(xfrm_state_alloc_acquire),
	DYNAMIC_HOOK(xfrm_state_free_security),
	DYNAMIC_HOOK(xfrm_state_delete_security),
	DYNAMIC_HOOK(xfrm_policy_lookup),
	DYNAMIC_HOOK(xfrm_decode_session),
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	DYNAMIC_HOOK(key_alloc),
	DYNAMIC_HOOK(key_free),
	DYNAMIC_HOOK(key_permission),
	DYNAMIC_HOOK(key_getsecurity),
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	DYNAMIC_HOOK(audit_rule_init),
	DYNAMIC_HOOK(audit_rule_known),
	DYNAMIC_HOOK(audit_rule_match),
	DYNAMIC_HOOK(audit_rule_free),
#endif /* CONFIG_AUDIT */
#ifdef CONFIG_BPF_SYSCALL
	DYNAMIC_HOOK(bpf),
	DYNAMIC_HOOK(bpf_map),
	DYNAMIC_HOOK(bpf_prog),
	DYNAMIC_HOOK(bpf_map_alloc_security),
	DYNAMIC_HOOK(bpf_map_free_security),
	DYNAMIC_HOOK(bpf_prog_alloc_security),
	DYNAMIC_HOOK(bpf_prog_free_security),
#endif /* CONFIG_BPF_SYSCALL */
};

/**
 * security_add_dynamic_hook - Add a dynamic hook to the dynamic hooks list
 * @hook: A populated dynamic_security_hook object
 *
 * returns 0 if the hook was successfully installed
 */
int security_add_dynamic_hook(struct dynamic_security_hook *hook)
{
	WARN_ON(!try_module_get(hook->owner));
	mutex_lock(&dynamic_hook_lock);
	list_add_tail_rcu(&hook->list, &dynamic_hooks[hook->type].head);
	mutex_unlock(&dynamic_hook_lock);
	static_branch_enable(&dynamic_hooks_keys[hook->type]);

	return 0;
}
EXPORT_SYMBOL_GPL(security_add_dynamic_hook);

void __init security_init_dynamic_hooks(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(dynamic_hooks); i++)
		INIT_LIST_HEAD(&dynamic_hooks[i].head);
}
