// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/percpu_counter.h>
#include <linux/percpu.h>
#include "dynamic.h"

struct seq_private_data {
	struct dynamic_hook *dh;
};

static void *dynamic_hooks_sop_start(struct seq_file *s, loff_t *pos)
{
	struct seq_private_data *pd = s->private;

	return seq_list_start_head(&pd->dh->head, *pos);
}

static void *dynamic_hooks_sop_next(struct seq_file *s, void *v, loff_t *pos)
{
	struct seq_private_data *pd = s->private;

	return seq_list_next(v, &pd->dh->head, pos);
}

static int dynamic_hooks_sop_show(struct seq_file *s, void *v)
{
	struct seq_private_data *pd = s->private;
	struct dynamic_security_hook *dsh;

	if (v == (void *)&pd->dh->head) {
		seq_puts(s, "name\tinvocations\tdenies\n");
		seq_printf(s, "all\t%lld\t%lld\n",
			   percpu_counter_sum(&pd->dh->invocation),
			   percpu_counter_sum(&pd->dh->deny));
		return 0;
	}

	dsh = list_entry(v, typeof(*dsh), list);
	seq_printf(s, "%s\t%lld\t%lld\n", dsh->lsm,
		   percpu_counter_sum(&dsh->invocation),
		   percpu_counter_sum(&dsh->deny));

	return 0;
}

static void dynamic_hooks_sop_stop(struct seq_file *s, void *v) { }

static const struct seq_operations dynamic_hooks_sops = {
	.start	= dynamic_hooks_sop_start,
	.next	= dynamic_hooks_sop_next,
	.show	= dynamic_hooks_sop_show,
	.stop	= dynamic_hooks_sop_stop,
};

static int security_dynamic_hook_open(struct inode *inode, struct file *file)
{
	struct seq_private_data *pd;

	pd = (struct seq_private_data *)__seq_open_private(file,
							   &dynamic_hooks_sops,
							   sizeof(*pd));

	if (!pd)
		return -ENOMEM;

	pd->dh = inode->i_private;

	return 0;
}

static const struct file_operations dynamic_hooks_fops = {
	.open		= security_dynamic_hook_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static struct dentry *dynamic_hooks_dir;
void securityfs_init_dynamic_hooks(void)
{
	struct dynamic_hook *dh;
	int i;

	dynamic_hooks_dir = securityfs_create_dir("dynamic_hooks", NULL);
	if (IS_ERR(dynamic_hooks_dir)) {
		pr_err("Unable to create dynamic hooks LSM directory - %ld\n",
			PTR_ERR(dynamic_hooks_dir));
		return;
	}

	for (i = 0; i < __MAX_DYNAMIC_SECURITY_HOOK; i++) {

		dh = &dynamic_hooks[i];
		dh->dentry = securityfs_create_file(dh->name, 0444,
						    dynamic_hooks_dir, dh,
						    &dynamic_hooks_fops);
		if (IS_ERR(dh->dentry))
			goto err;
	}
	return;

err:
	pr_err("Unable to create dynamic hook directory - %s - %ld\n",
	       dh->name, PTR_ERR(dh->dentry));
}
