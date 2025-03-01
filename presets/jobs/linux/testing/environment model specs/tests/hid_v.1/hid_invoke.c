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

int ldv_start(struct hid_device *hdev)
{
	ldv_invoke_reached();
	return 0;
}

void ldv_hid_stop(struct hid_device *hdev)
{
	ldv_invoke_reached();
}

struct hid_ll_driver ldv_driver = {
	.start = ldv_start,
	.stop = ldv_hid_stop
};

struct hid_device ldvdev = {
    .ll_driver = & ldv_driver
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return hid_add_device(&ldvdev);
}

static void __exit ldv_exit(void)
{
	hid_destroy_device(&ldvdev);
}

module_init(ldv_init);
module_exit(ldv_exit);
