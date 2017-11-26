#include <linux/lsm_hooks.h>
#include <linux/srcu.h>
#include <linux/list.h>
#include <linux/jump_label.h>

#ifdef CONFIG_SECURITY_DYNAMIC_HOOKS
extern struct static_key_false dynamic_hooks_keys[];

struct dynamic_hook {
	const char		*name;
	struct list_head	head;
};

extern struct dynamic_hook dynamic_hooks[];
extern void security_init_dynamic_hooks(void);
#else
static inline void security_init_dynamic_hooks(void) {}
#endif
