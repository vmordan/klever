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
#include <target/target_core_base.h>
#include <target/target_core_backend.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int flip_a_coin;

struct se_device * ldv_alloc_device(struct se_hba *hba, const char *name)
{
	struct se_device *res;

	ldv_invoke_callback();
	res = ldv_undef_ptr();
	if (res)
		ldv_probe_up();
	return res;
}

static void ldv_free_device(struct se_device *device)
{
	ldv_release_down();
	ldv_invoke_callback();
}

static struct se_subsystem_api ldv_driver = {
	.alloc_device = ldv_alloc_device,
	.free_device = ldv_free_device,
};

static int __init ldv_init(void)
{
	int ret = ldv_undef_int();
	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		ldv_register();
		ret = transport_subsystem_register(&ldv_driver);
		if (ret)
			ldv_deregister();
	}
	return ret;
}

static void __exit ldv_exit(void)
{
	if (flip_a_coin) {
		transport_subsystem_release(&ldv_driver);
		ldv_deregister();
	}
}

module_init(ldv_init);
module_exit(ldv_exit);
