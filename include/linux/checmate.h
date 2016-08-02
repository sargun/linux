#ifndef _LINUX_CHECMATE_H_
#define _LINUX_CHECMATE_H_ 1
#include <linux/security.h>

enum checmate_hook_num {
	/* CONFIG_SECURITY_NET hooks */
	CHECMATE_HOOK_UNIX_STREAM_CONNECT,
	CHECMATE_HOOK_UNIX_MAY_SEND,
	CHECMATE_HOOK_SOCKET_CREATE,
	CHECMATE_HOOK_SOCKET_POST_CREATE,
	CHECMATE_HOOK_SOCKET_BIND,
	CHECMATE_HOOK_SOCKET_CONNECT,
	CHECMATE_HOOK_SOCKET_LISTEN,
	CHECMATE_HOOK_SOCKET_ACCEPT,
	CHECMATE_HOOK_SOCKET_SENDMSG,
	CHECMATE_HOOK_SOCKET_RECVMSG,
	CHECMATE_HOOK_SOCKET_GETSOCKNAME,
	CHECMATE_HOOK_SOCKET_GETPEERNAME,
	CHECMATE_HOOK_SOCKET_GETSOCKOPT,
	CHECMATE_HOOK_SOCKET_SETSOCKOPT,
	CHECMATE_HOOK_SOCKET_SHUTDOWN,
	CHECMATE_HOOK_SOCKET_SOCK_RCV_SKB,
	CHECMATE_HOOK_SK_FREE_SECURITY,
	__CHECMATE_HOOK_MAX,
};

/* CONFIG_NET_SECURITY contexts */
struct checmate_unix_stream_connect_ctx {
	struct sock *sock;
	struct sock *other;
	struct sock *newsk;
};

struct checmate_unix_may_send_ctx {
	struct socket *sock;
	struct socket *other;
};

struct checmate_socket_create_ctx {
	int family;
	int type;
	int protocol;
	int kern;
};

struct checmate_socket_bind_ctx {
	struct socket *sock;
	struct sockaddr *address;
	int addrlen;
};

struct checmate_socket_connect_ctx {
	struct socket *sock;
	struct sockaddr *address;
	int addrlen;
};

struct checmate_socket_listen_ctx {
	struct socket *sock;
	int backlog;
};

struct checmate_socket_accept_ctx {
	struct socket *sock;
	struct socket *newsock;
};

struct checmate_socket_sendmsg_ctx {
	struct socket *sock;
	struct msghdr *msg;
	int size;
};

struct checmate_socket_recvmsg_ctx {
	struct socket *sock;
	struct msghdr *msg;
	int size;
	int flags;
};

struct checmate_socket_sock_rcv_skb_ctx {
	struct sock *sk;
	struct sk_buff *skb;
};

struct checmate_sk_free_security_ctx {
	struct sock *sk;
};

struct checmate_ctx {
	int hook;
	union {
/* CONFIG_PATH_NET contexts */
		struct checmate_unix_stream_connect_ctx	unix_stream_connect;
		struct checmate_unix_may_send_ctx	unix_may_send;
		struct checmate_socket_create_ctx	socket_create;
		struct checmate_socket_bind_ctx		socket_bind;
		struct checmate_socket_connect_ctx	socket_connect;
		struct checmate_socket_listen_ctx	socket_listen;
		struct checmate_socket_accept_ctx	socket_accept;
		struct checmate_socket_sendmsg_ctx	socket_sendmsg;
		struct checmate_socket_recvmsg_ctx	socket_recvmsg;
		struct checmate_socket_sock_rcv_skb_ctx	socket_sock_rcv_skb;
		struct checmate_sk_free_security_ctx	sk_free_security;
	};
};

#endif /* _LINUX_CHECMATE_H_ */
