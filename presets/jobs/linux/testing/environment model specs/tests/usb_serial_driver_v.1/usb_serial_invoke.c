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
#include <linux/tty.h>
#include <linux/usb.h>
#include <linux/usb/serial.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

const struct usb_device_id *id_table;

int ldv_probe(struct usb_serial *serial, const struct usb_device_id *id)
{
	ldv_invoke_reached();
	return 0;
}

void ldv_release(struct usb_serial *serial)
{
	ldv_invoke_reached();
}

static struct usb_serial_driver ldv_driver = {
	.probe = ldv_probe,
	.release = ldv_release,
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return usb_serial_register(& ldv_driver);
}

static void __exit ldv_exit(void)
{
	 usb_serial_deregister(& ldv_driver);
}

module_init(ldv_init);
module_exit(ldv_exit);
