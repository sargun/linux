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

#include <linux/prctl.h>
#include <linux/checmate.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/cgroup.h>
#include <net/sock.h>
#include <net/request_sock.h>

#define CHECMATE_CFTYPE(HOOK, NAME) 			\
	{						\
		.name		= NAME,			\
		.private	= HOOK,			\
		.read_u64	= checmate_read_u64,	\
		.write_s64	= checmate_write_s64,	\
		.flags		= CFTYPE_NOT_ON_ROOT	\
	}

extern void register_checmate_prog_ops(void);

struct checmate_program_instance {
	struct list_head	list;
	struct bpf_prog		*prog;
};

struct checmate_css {
	struct cgroup_subsys_state	css;
	struct mutex			mutex;
	struct list_head 		hooks[__CHECMATE_HOOK_MAX];
};

/* cgroup code */
static struct checmate_css *css_checmate(struct cgroup_subsys_state *css)
{
	return container_of(css, struct checmate_css, css);
}

static struct checmate_css *parent_checmate(struct checmate_css *checmate)
{
	return css_checmate(checmate->css.parent);
}

static struct cgroup_subsys_state *
checmate_css_alloc(struct cgroup_subsys_state *parent)
{
	struct checmate_css *checmate;
	int i;

	checmate = kzalloc(sizeof(*checmate), GFP_KERNEL);
	if (!checmate)
		return ERR_PTR(-ENOMEM);

	for (i = 0; i < ARRAY_SIZE(checmate->hooks); i++) {
		INIT_LIST_HEAD(&checmate->hooks[i]);
		mutex_init(&checmate->mutex);
	}

	return &checmate->css;
}

/*
 * checmate_hook_free - Deallocate, and release references for a given hook
 * @hook: The hook
 *
 * Always succeeds.
 */
static void checmate_hook_free(struct list_head *hook)
{
	struct checmate_program_instance *instance, *next;

	list_for_each_entry_safe(instance, next, hook, list) {
		list_del(&instance->list);
		bpf_prog_put(instance->prog);
		kfree(instance);
	}
}

/*
 * checmate_css_free - Callback for css_free
 * @css: The cgroup_subsys_state to be freed
 *
 * cgroups ensures that there are no uses, so there's no need to lock, nor
 * synchronize
 */
static void checmate_css_free(struct cgroup_subsys_state *css)
{
	struct checmate_css *checmate = css_checmate(css);
	int i;

	for (i = 0; i < ARRAY_SIZE(checmate->hooks); i++)
		checmate_hook_free(&checmate->hooks[i]);

	kfree(checmate);
}

/*
 * checmate_add_to_hook - Add BPF program to a checmate hook
 * @hook: The hook
 * @prog: A checmate BPF program
 *
 * Checks if the program is already part of the hook, and only adds new
 * programs.
 *
 * Returns 0 on success. -errno on failure.
 *
 * Requires that the hook's mutex is held during the operation.
 */
static int checmate_add_to_hook(struct list_head *hook, struct bpf_prog *prog)
{
	struct checmate_program_instance *instance;
	int rc = 0;

	list_for_each_entry(instance, hook, list) {
		if (instance->prog == prog) {
			bpf_prog_put(prog);
			rc = -EEXIST;
			goto err;
		}
	}

	instance = kmalloc(sizeof(*instance), GFP_KERNEL);
	if (!instance) {
		rc = -ENOMEM;
		goto err;
	}

	instance->prog = prog;
	list_add_tail_rcu(&instance->list, hook);
	return rc;

err:
	bpf_prog_put(prog);
	return rc;
}

/*
 * checmate_remove_from_hook - Remove BPF program from a checmate hook
 * @hook: The hook
 * @prog: A checmate BPF program
 *
 * Returns 0 on success. -errno on failure.
 *
 * Requires that the hook's mutex is held during the operation.
 */
static int checmate_remove_from_hook(struct list_head *hook,
				     struct bpf_prog *prog)
{
	struct checmate_program_instance *instance, *next;
	int rc = -ENOENT;

	list_for_each_entry_safe(instance, next, hook, list) {
		if (instance->prog == prog) {
			list_del_rcu(&instance->list);
			synchronize_rcu();
			bpf_prog_put(instance->prog);
			kfree(instance);
			rc = 0;
			break;
		}
	}
	bpf_prog_put(prog);

	return rc;
}

/*
 * checmate_reset_hook - Remove all BPF programs from a checmate hook
 * @hook: The hook
 *
 * Always succeeds.
 *
 * Requires that the hook's mutex is held during the operation.
 */
static void checmate_reset_hook(struct list_head *hook)
{
	struct checmate_program_instance *instance, *next;

	list_for_each_entry_safe(instance, next, hook, list) {
		list_del_rcu(&instance->list);
		synchronize_rcu();
		bpf_prog_put(instance->prog);
		kfree(instance);
	}
}

/*
 * checmate_write_s64 - Handle a write to the checmate cgroup control file
 * @css: The given cgroup state that own's the hook
 * @cft: The given cftype that is being referenced, used to get the hook id.
 * @val: The bpf fd, or 0 that is involved in the operation.
 *
 * val == 0: Reset all programs in hook.
 * val > 0: Add the given program.
 * val < 0: Remove the given program.
 *
 * Returns 0 on success. -errno on failure.
 */
static int checmate_write_s64(struct cgroup_subsys_state *css,
			      struct cftype *cft, s64 val)
{
	struct checmate_css *checmate = css_checmate(css);
	struct list_head *hook;
	struct bpf_prog *prog;
	int rc = 0;

	hook = &checmate->hooks[cft->private];
	mutex_lock(&checmate->mutex);
	if (val == 0) {
		checmate_reset_hook(hook);
		goto out;
	}

	/* If we're not reseting, we have to load, and check the program */
	prog = bpf_prog_get_type(abs(val), BPF_PROG_TYPE_CHECMATE);
	if (IS_ERR(prog))
		return PTR_ERR(prog);

	if (val > 0)
		rc = checmate_add_to_hook(hook, prog);
	else
		rc = checmate_remove_from_hook(hook, prog);

out:
	mutex_unlock(&checmate->mutex);
	return rc;
}

/*
 * checmate_read_u64 - Read the number of programs loaded into a given hook
 * @css: The given cgroup state that own's the hook
 * @cft: The given cftype that is being referenced, used to get the hook id.
 *
 *
 * Returns number of programs loaded into hook. Always succeeds.
 */
static u64 checmate_read_u64(struct cgroup_subsys_state *css,
			     struct cftype *cft)
{
	struct checmate_css *checmate = css_checmate(css);
	struct checmate_program_instance *instance;
	struct list_head *hook;
	u64 i = 0;

	hook = &checmate->hooks[cft->private];
	rcu_read_lock();
	list_for_each_entry_rcu(instance, hook, list)
		i++;
	rcu_read_unlock();

	return i;
}

static struct cftype checmate_files[] = {
#ifdef CONFIG_SECURITY_NETWORK
	CHECMATE_CFTYPE(CHECMATE_HOOK_UNIX_STREAM_CONNECT,
			"unix_stream_connect"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_UNIX_MAY_SEND,
			"unix_may_send"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_CREATE, "socket_create"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_BIND, "socket_bind"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_CONNECT, "socket_connect"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_LISTEN, "socket_listen"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_ACCEPT, "socket_accept"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_SENDMSG, "socket_sendmsg"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_RECVMSG, "socket_recvmsg"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_SHUTDOWN, "socket_shutdown"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SOCKET_SOCK_RCV_SKB,
			"socket_sock_rcv_skb"),
	CHECMATE_CFTYPE(CHECMATE_HOOK_SK_FREE_SECURITY, "sk_free_security"),
#endif /* CONFIG_SECURITY_NETWORK */
	{}
};

/* struct cgroup_subsys checmate_cgrp_subsys: checmate LSM cgroup subsys */
struct cgroup_subsys checmate_cgrp_subsys = {
	.css_alloc	= checmate_css_alloc,
	.css_free	= checmate_css_free,
	.dfl_cftypes	= checmate_files,
};

/*
 * check_checmate_filters - Run all the BPF programs associated with a hook
 * @css: A pointer to the checmate css
 * @ctx: A pointer to the Checmate ctx
 *
 * Return 0 on success, on first hook erroring, the error is returned
 * to the caller.
 */
static int check_checmate_filters(struct checmate_css *checmate,
				  struct checmate_ctx *ctx)
{
	struct checmate_program_instance *instance;
	struct list_head *hook;
	int rc = 0;

	hook = &checmate->hooks[ctx->hook];

	list_for_each_entry_rcu(instance, hook, list) {
		rc = BPF_PROG_RUN(instance->prog, (void *)ctx);
		if (rc)
			break;
	}
	return rc;
}

/*
 * call_bpf_int_hook - Walk the cgroup heirarchy, running filters up the chain
 * @hook: The Hook ID
 * @css: A pointer to the checmate css
 * @cgrp: A pointer to the cgroup we're in, may be null or err
 *
 * Return 0 on success, on first hook erroring, the error is returned
 * to the caller.
 *
 * Requires that the context struct is populated before passing, but
 * the actual ctx->hook number is set by the function. It also performs
 * css_put, as we assume a reference count was incremented in order
 * to get it.
 */
static int call_bpf_int_hook(int hook, struct cgroup_subsys_state *css,
			     struct checmate_ctx *ctx)
{
	struct checmate_css *checmate;
	int rc = 0;

	ctx->hook = hook;

	/* Fail open if we can't find the css / cgroup */
	if (IS_ERR_OR_NULL(css))
		goto out;

	rcu_read_lock();

	for(checmate = css_checmate(css); parent_checmate(checmate);
	    checmate = parent_checmate(checmate)) {
		rc = check_checmate_filters(checmate, ctx);
		if (rc)
			break;
	}

	rcu_read_unlock();

out:
	css_put(css);
	return rc;
}

/*
 * call_bpf_void_hook - Run all the BPF programs associated with a hook
 * Wrapper around call_bpf_int_hook.
 */
static void call_bpf_void_hook(int hook, struct cgroup_subsys_state *css,
			       struct checmate_ctx *ctx)
{
	call_bpf_int_hook(hook, css, ctx);
}


/*
 * css_from_sk - Get the checmate CSS for a sk, and increment the refcnt
 * @sk: The struct sock we're trying to get the CSS for.
 *
 * Return css with refcnt on success, or ERR_PTR on failure.
 */
static struct cgroup_subsys_state * css_from_sk(struct sock *sk)
{
	struct cgroup *cgrp;

	if (!sk_fullsock(sk))
		return ERR_PTR(-EINVAL);
	cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	return cgroup_get_e_css(cgrp, &checmate_cgrp_subsys);
}

/*
 * css_from_sock - Get the checmate CSS for a socket, and increment the refcnt
 * @sock: The struct socket we're trying to get the CSS for.
 *
 * Return css with refcnt on success, or ERR_PTR on failure. It's basically a
 * wrapper around css_from_sk.
 */
static struct cgroup_subsys_state * css_from_sock(struct socket *sock)
{
	struct sock *sk;

	sk = sock->sk;
	if (!sk)
		return ERR_PTR(-ENOENT);

	return css_from_sk(sk);
}

/*
 * css_from_sock - Get the checmate CSS for the current task context.
 *
 * Return css with refcnt on success, or ERR_PTR on failure. LSMs should
 * never call from an interrupt.
 */
static struct cgroup_subsys_state * css_from_current(void)
{
	struct task_struct *task = current;
	struct cgroup_subsys_state *css;

	if (unlikely(!task))
		return ERR_PTR(-ENOENT);

	css = task_get_css(task, checmate_cgrp_id);
	return css;
}

/* Checmate hooks */
#ifdef CONFIG_SECURITY_NETWORK
int checmate_unix_stream_connect(struct sock *sock, struct sock *other,
				 struct sock *newsk)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sk(sock);
	ctx.unix_stream_connect.sock = sock;
	ctx.unix_stream_connect.other = other;
	ctx.unix_stream_connect.newsk = newsk;
	return call_bpf_int_hook(CHECMATE_HOOK_UNIX_STREAM_CONNECT, css, &ctx);
}

static int checmate_unix_may_send(struct socket *sock, struct socket *other)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.unix_may_send.sock = sock;
	ctx.unix_may_send.other = other;
	return call_bpf_int_hook(CHECMATE_HOOK_UNIX_MAY_SEND, css, &ctx);
}

static int checmate_socket_create(int family, int type, int protocol, int kern)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_current();
	ctx.socket_create.family = family;
	ctx.socket_create.type = type;
	ctx.socket_create.protocol = protocol;
	ctx.socket_create.kern = kern;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_CREATE, css, &ctx);
}

static int checmate_socket_bind(struct socket *sock, struct sockaddr *address,
				int addrlen)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_bind.sock = sock;
	ctx.socket_bind.address = address;
	ctx.socket_bind.addrlen = addrlen;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_BIND, css, &ctx);
}

static int checmate_socket_connect(struct socket *sock,
				   struct sockaddr *address, int addrlen)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_connect.sock = sock;
	ctx.socket_connect.address = address;
	ctx.socket_connect.addrlen = addrlen;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_CONNECT, css, &ctx);
}

static int checmate_socket_listen(struct socket *sock, int backlog)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_listen.sock = sock;
	ctx.socket_listen.backlog = backlog;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_LISTEN, css, &ctx);
}

static int checmate_socket_accept(struct socket *sock, struct socket *newsock)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_accept.sock = sock;
	ctx.socket_accept.newsock = newsock;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_ACCEPT, css, &ctx);
}

static int checmate_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				   int size)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_sendmsg.sock = sock;
	ctx.socket_sendmsg.msg = msg;
	ctx.socket_sendmsg.size = size;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_SENDMSG, css, &ctx);
}

static int checmate_socket_recvmsg(struct socket *sock, struct msghdr *msg, 
				   int size, int flags)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sock(sock);
	ctx.socket_recvmsg.sock = sock;
	ctx.socket_recvmsg.msg = msg;
	ctx.socket_recvmsg.size = size;
	ctx.socket_recvmsg.flags = flags;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_RECVMSG, css, &ctx);
}

static int checmate_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sk(sk);
	ctx.socket_sock_rcv_skb.sk = sk;
	ctx.socket_sock_rcv_skb.skb = skb;
	return call_bpf_int_hook(CHECMATE_HOOK_SOCKET_SOCK_RCV_SKB, css, &ctx);
}

static void checmate_sk_free_security(struct sock *sk)
{
	struct cgroup_subsys_state *css;
	struct checmate_ctx ctx;

	css = css_from_sk(sk);
	ctx.sk_free_security.sk = sk;
	return call_bpf_void_hook(CHECMATE_HOOK_SK_FREE_SECURITY, css, &ctx);
}

#endif /* CONFIG_SECURITY_NETWORK */

static struct security_hook_list checmate_hooks[] = {
#ifdef CONFIG_SECURITY_NETWORK
	LSM_HOOK_INIT(unix_stream_connect, checmate_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, checmate_unix_may_send),
	LSM_HOOK_INIT(socket_create, checmate_socket_create),
	LSM_HOOK_INIT(socket_bind, checmate_socket_bind),
	LSM_HOOK_INIT(socket_connect, checmate_socket_connect),
	LSM_HOOK_INIT(socket_listen, checmate_socket_listen),
	LSM_HOOK_INIT(socket_accept, checmate_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, checmate_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, checmate_socket_recvmsg),
	LSM_HOOK_INIT(socket_sock_rcv_skb, checmate_socket_sock_rcv_skb),
	LSM_HOOK_INIT(sk_free_security, checmate_sk_free_security),
#endif /* CONFIG_SECURITY_NETWORK */
};

static int __init checmate_setup(void)
{
	pr_info("Checmate activating.\n");
	register_checmate_prog_ops();
	security_add_hooks(checmate_hooks, ARRAY_SIZE(checmate_hooks));
	return 0;
}
late_initcall(checmate_setup);
