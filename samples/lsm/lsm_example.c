/*
 * This sample hooks into the "path_chroot"
 *
 * Once you run it, the following will not be allowed:
 * date --set="October 21 2015 16:29:00 PDT"
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>

static const char lsm_name[] = "example";

static int settime_cb(const struct timespec *ts, const struct timezone *tz)
{
	/* We aren't allowed to travel to October 21 2015 16:29 PDT */
	if (ts->tv_sec >= 1445470140 && ts->tv_sec < 1445470200)
		return -EPERM;

	return 0;
}

DYNAMIC_SECURITY_HOOK(my_hook, lsm_name, settime, settime_cb);

static int __init lsm_init(void)
{
	int ret;

	ret = security_add_dynamic_hook(&my_hook);
	if (!ret)
		pr_info("Successfully installed example dynamic LSM\n");
	else
		pr_err("Unable to install dynamic LSM - %d\n", ret);

	return ret;
}

module_init(lsm_init)
MODULE_LICENSE("GPL");
