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
#include <linux/usb.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int ldv_probe(struct usb_interface *intf, const struct usb_device_id *id)
{
	ldv_invoke_reached();
	return 0;
}

static void ldv_disconnect(struct usb_interface *intf)
{
	ldv_invoke_reached();
}

static struct usb_driver ldv_driver = {
	.name = "ldv-test",
	.probe = ldv_probe,
	.disconnect = ldv_disconnect
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return usb_register(&ldv_driver);
}

static void __exit ldv_exit(void)
{
	usb_deregister(&ldv_driver);
}

module_init(ldv_init);
module_exit(ldv_exit);
