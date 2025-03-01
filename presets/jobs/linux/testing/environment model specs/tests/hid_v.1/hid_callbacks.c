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
#include <linux/hid.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int flip_a_coin;

int ldv_start(struct hid_device *hdev)
{
	ldv_probe_up();
	return 0;
}

void ldv_hid_stop(struct hid_device *hdev)
{
	ldv_release_down();
}

int ldv_open(struct hid_device *hdev)
{
	ldv_probe_up();
	return 0;
}

void ldv_close(struct hid_device *hdev)
{
	ldv_release_down();
}

struct hid_ll_driver ldv_driver = {
	.start = ldv_start,
	.stop = ldv_hid_stop,
	.open = ldv_open,
	.close = ldv_close
};

struct hid_device ldvdev = {
    .ll_driver = & ldv_driver
};

static int __init ldv_init(void)
{
	int ret = ldv_undef_int();
	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		ldv_register();
		ret = hid_add_device(&ldvdev);
		if (ret)
			ldv_deregister();
	}
	return ret;
}

static void __exit ldv_exit(void)
{
	if (flip_a_coin) {
		hid_destroy_device(&ldvdev);
		ldv_deregister();
	}
}

module_init(ldv_init);
module_exit(ldv_exit);
