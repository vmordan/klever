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
#include <linux/tty_driver.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

int flip_a_coin;
struct tty_driver *driver;
struct tty_port port;
struct device *device;
unsigned int lines;
unsigned indx;

int ldv_open(struct tty_struct * tty, struct file * filp)
{
	return 0;
}

void ldv_close(struct tty_struct * tty, struct file * filp)
{
	/* pass */
}

static struct tty_operations ldv_tty_ops = {
	.open = ldv_open,
	.close = ldv_close
};

static int ldv_activate(struct tty_port *tport, struct tty_struct *tty)
{
	ldv_invoke_callback();
	return 0;
}

static void ldv_shutdown(struct tty_port *tport)
{
	ldv_invoke_callback();
}

static const struct tty_port_operations ldv_tty_port_ops = {
	.activate = ldv_activate,
	.shutdown = ldv_shutdown,
};

static int __init ldv_init(void)
{
	int res = ldv_undef_int();
	flip_a_coin = ldv_undef_int();
	if (flip_a_coin) {
		driver = alloc_tty_driver(lines);
		if (driver) {
			tty_set_operations(driver, &ldv_tty_ops);
			ldv_register();
			res = tty_register_driver(driver);
			if (res) {
				put_tty_driver(driver);
				ldv_deregister();
			}
			else {
				tty_port_init(& port);
				port.ops = & ldv_tty_port_ops;
				res = tty_port_register_device(& port, driver, ldv_undef_int(), device);
				if (res) 
					ldv_deregister();
			}
		}
	}
	return res;
}

static void __exit ldv_exit(void)
{
	if (flip_a_coin) {
		tty_port_destroy(&port);
		tty_unregister_driver(driver);
		put_tty_driver(driver);
		ldv_deregister();
	}
}

module_init(ldv_init);
module_exit(ldv_exit);
