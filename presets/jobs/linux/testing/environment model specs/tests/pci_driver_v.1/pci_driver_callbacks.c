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
#include <linux/pci.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int flip_a_coin;

static int ldv_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int res;

	ldv_invoke_callback();
	res = ldv_undef_int();
	if (!res)
		ldv_probe_up();
	return res;
}

static void ldv_remove(struct pci_dev *dev)
{
	ldv_release_completely();
	ldv_invoke_callback();
}

static int ldv_suspend(struct pci_dev *dev, pm_message_t state)
{
	ldv_probe_up();
	ldv_invoke_middle_callback();
	return 0;
}

static int ldv_suspend_later(struct pci_dev *dev, pm_message_t state)
{
	ldv_probe_up();
	ldv_invoke_middle_callback();
	return 0;
}

static int ldv_resume_early(struct pci_dev *dev)
{
	ldv_release_down();
	ldv_invoke_middle_callback();
	return 0;
}

static int ldv_resume(struct pci_dev *dev)
{
	ldv_release_down();
	ldv_invoke_middle_callback();
	return 0;
}

static void ldv_shutdown(struct pci_dev *dev)
{
	ldv_invoke_middle_callback();
}

static struct pci_driver ldv_driver = {
	.name =	"ldv-test",
	.probe = ldv_probe,
	.remove = ldv_remove,
	.suspend = ldv_suspend,
	.suspend_late = ldv_suspend_later,
	.resume_early = ldv_resume_early,
	.resume = ldv_resume,
	.shutdown = ldv_shutdown
};

static int __init ldv_init(void)
{
	int ret = ldv_undef_int();
	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		ldv_register();
		ret = pci_register_driver(&ldv_driver);
		if (ret)
			ldv_deregister();
	}
	return ret;
}

static void __exit ldv_exit(void)
{
	if (flip_a_coin) {
		pci_unregister_driver(&ldv_driver);
		ldv_deregister();
	}
}

module_init(ldv_init);
module_exit(ldv_exit);
