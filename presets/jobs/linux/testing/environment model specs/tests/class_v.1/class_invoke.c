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
#include <linux/device.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

static int ldv_add_dev(struct device *dev, struct class_interface *intf)
{
	ldv_invoke_reached();
	return 0;
}

static void ldv_remove_dev(struct device *dev, struct class_interface *intf)
{
	ldv_invoke_reached();
}

static struct class_interface ldv_driver = {
	.add_dev = ldv_add_dev,
	.remove_dev = ldv_remove_dev,
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return class_interface_register(&ldv_driver);
}

static void __exit ldv_exit(void)
{
	class_interface_unregister(&ldv_driver);
}

module_init(ldv_init);
module_exit(ldv_exit);
