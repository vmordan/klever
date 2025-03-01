/*
 * Copyright (c) 2018 ISP RAS (http://www.ispras.ru)
 * Ivannikov Institute for System Programming of the Russian Academy of Sciences
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * ee the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

struct net_device dev;
struct mutex *ldv_envgen;

static netdev_tx_t ldv_xmit(struct sk_buff *skb, struct net_device *dev)
{
	ldv_invoke_reached();
	return 0;
}

static int ldv_open(struct net_device *dev)
{
	ldv_invoke_reached();
	return 0;
}

static int ldv_close(struct net_device *dev)
{
	ldv_invoke_reached();
	return 0;
}

static const struct net_device_ops ldv_ops = {
	.ndo_open	= ldv_open,
	.ndo_stop	= ldv_close,
	.ndo_start_xmit = ldv_xmit,
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	dev.netdev_ops = &ldv_ops;
	return register_netdev(&dev);
}

static void __exit ldv_exit(void)
{
	unregister_netdev(&dev);
}

module_init(ldv_init);
module_exit(ldv_exit);
