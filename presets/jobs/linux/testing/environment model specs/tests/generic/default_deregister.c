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
#include <verifier/nondet.h>
#include <linux/emg/test_model.h>
#include "ldvops.h"

int ldv_probe(struct ldv_resource *arg)
{
	ldv_invoke_callback();
	return 0;
}

void ldv_disconnect(struct ldv_resource *arg)
{
	ldv_invoke_callback();
}

static struct ldv_driver ops = {
	.probe = ldv_probe,
	.disconnect = ldv_disconnect
};

static int __init ldv_init(void)
{
	int flip_a_coin;

	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		ldv_register();
		if (!ldv_driver_register(& ops)) {
			ldv_driver_deregister(& ops);
			ldv_deregister();
		}
	}
	return 0;
}

static void __exit ldv_exit(void)
{
	/* pass */
}

module_init(ldv_init);
module_exit(ldv_exit);
