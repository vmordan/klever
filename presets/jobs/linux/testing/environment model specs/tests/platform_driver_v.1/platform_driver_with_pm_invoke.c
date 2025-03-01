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
#include <linux/platform_device.h>
#include <linux/pm.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

static int ldvprobe(struct platform_device *op)
{
	return 0;
}

static int ldvremove(struct platform_device *op)
{
	return 0;
}

static int test_suspend(struct device *dev)
{
	ldv_invoke_reached();
	return 0;
}

static int test_resume(struct device *dev)
{
	ldv_invoke_reached();
	return 0;
}

static SIMPLE_DEV_PM_OPS(test_pm_ops, test_suspend, test_resume);

static struct platform_driver ldv_platform_driver = {
	.probe = ldvprobe,
	.remove = ldvremove,
	.driver = {
		.name = "ldv",
		.owner = THIS_MODULE,
		.pm = &test_pm_ops
	},
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return platform_driver_register(&ldv_platform_driver);
}

static void __exit ldv_exit(void)
{
	platform_driver_unregister(&ldv_platform_driver);
}

module_init(ldv_init);
module_exit(ldv_exit);
