/*
 * IPVS:        Power of two choices scheduling module
 *
 * Authors:     Sargun Dhillon <sargun@sargun.me>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 */


#define KMSG_COMPONENT "IPVS"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <net/ip_vs.h>
#include <linux/random.h>

static struct ip_vs_dest *ip_vs_p2c_schedule(struct ip_vs_service *svc,
					     const struct sk_buff *skb,
					     struct ip_vs_iphdr *iph)
{
	/* Uses reservoir sampling algorithm */
	struct ip_vs_dest *reservoir[2];
	struct ip_vs_dest *dest, *chosen = NULL;
	long i, j, seen_backends = 0;
	unsigned int loh = 0, doh;

	/* Populate the reservoir */
	list_for_each_entry_rcu(dest, &svc->destinations, n_list) {
		if ((dest->flags & IP_VS_DEST_F_OVERLOAD) ||
		    atomic_read(&dest->weight) == 0)
			continue;

		/* First, fill up the reservoir */
		if (seen_backends < ARRAY_SIZE(reservoir)) {
			reservoir[seen_backends] = dest;
		} else {
			j = get_random_long() % seen_backends;
			if (j < ARRAY_SIZE(reservoir))
				reservoir[j] = dest;
		}
		seen_backends++;
	}

	/* Choose the least cost backend amongst the choices in the reservoir */
	for (i = 0; i < ARRAY_SIZE(reservoir) && i < seen_backends; i++) {
		doh = ip_vs_dest_conn_overhead(reservoir[i]);
		if (!chosen || doh < loh) {
			chosen = reservoir[i];
			loh = doh;
		}
	}

	if (!chosen)
		ip_vs_scheduler_err(svc, "no destination available");

	return chosen;
}


static struct ip_vs_scheduler ip_vs_p2c_scheduler =
{
	.name =			"p2c",
	.refcnt =		ATOMIC_INIT(0),
	.module =		THIS_MODULE,
	.n_list =		LIST_HEAD_INIT(ip_vs_p2c_scheduler.n_list),
	.schedule =		ip_vs_p2c_schedule,
};


static int __init ip_vs_p2c_init(void)
{
	return register_ip_vs_scheduler(&ip_vs_p2c_scheduler);
}

static void __exit ip_vs_p2c_cleanup(void)
{
	unregister_ip_vs_scheduler(&ip_vs_p2c_scheduler);
	synchronize_rcu();
}

module_init(ip_vs_p2c_init);
module_exit(ip_vs_p2c_cleanup);
MODULE_LICENSE("GPL");