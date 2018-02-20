/*
 * This sample hooks into the "path_chroot"
 *
 * Once you run it, the following will not be allowed:
 * date --set="October 21 2015 16:29:00 PDT"
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>

static int settime_cb(const struct timespec *ts, const struct timezone *tz)
{
	/* We aren't allowed to travel to October 21 2015 16:29 PDT */
	if (ts->tv_sec >= 1445470140 && ts->tv_sec < 1445470200)
		return -EPERM;

	return 0;
}

static struct security_hook_list sample_hooks[] = {
	LSM_HOOK_INIT(settime, settime_cb),
};

static int __init lsm_init(void)
{
	security_add_dynamic_hooks(sample_hooks, ARRAY_SIZE(sample_hooks),
				   "sample");
	return 0;
}

module_init(lsm_init)
MODULE_LICENSE("GPL");
