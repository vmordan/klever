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
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

unsigned int irq_id = 100;
void * data;

static irqreturn_t irq_handler(int irq_id, void * data)
{
	ldv_invoke_reached();
	return IRQ_HANDLED;
}

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return request_irq(irq_id, irq_handler, 0, "ldv interrupt", data);
}

static void __exit ldv_exit(void)
{
	free_irq(irq_id, data);
}

module_init(ldv_init);
module_exit(ldv_exit);
