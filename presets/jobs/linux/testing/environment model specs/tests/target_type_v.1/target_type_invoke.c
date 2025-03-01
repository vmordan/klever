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
#include <linux/device-mapper.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

static int ldv_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	ldv_invoke_reached();
	return 0;
}

static void ldv_dtr(struct dm_target *ti)
{
	ldv_invoke_reached();
}

static struct target_type ldv_target = {
	.name		= "ldv",
	.module	  = THIS_MODULE,
	.ctr		 = ldv_ctr,
	.dtr		 = ldv_dtr,
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return dm_register_target(&ldv_target);
}

static void __exit ldv_exit(void)
{
	dm_unregister_target(&ldv_target);
}

module_init(ldv_init);
module_exit(ldv_exit);
