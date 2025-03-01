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
#include <scsi/scsi_device.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int flip_a_coin;

static int ldv_attach(struct scsi_device *sdev)
{
	int res;

	ldv_invoke_callback();
	res = ldv_undef_int();
	if (!res)
		ldv_probe_up();
	return res;
}

static void ldv_detach(struct scsi_device *sdev)
{
	ldv_release_down();
	ldv_invoke_callback();
}

static struct scsi_device_handler ldv_test_struct = {
	.attach = ldv_attach,
	.detach = ldv_detach,
};

static int __init test_init(void)
{
	int ret = ldv_undef_int();
	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		ldv_register();
		ret = scsi_register_device_handler(&ldv_test_struct);
		if (ret)
			ldv_deregister();
	}
	return ret;
}

static void __exit test_exit(void)
{
	if (flip_a_coin) {
		scsi_unregister_device_handler(&ldv_test_struct);
		ldv_deregister();
	}
}

module_init(test_init);
module_exit(test_exit);
