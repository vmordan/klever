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
#include <linux/gfp.h>
#include "memory.h"

static irqreturn_t ldv_handler(int irq, void *dev_id)
{
	ldv_alloc(GFP_ATOMIC);
	return IRQ_HANDLED;
}

static int __init ldv_init(void)
{
	unsigned int irq = ldv_undef_uint();
	unsigned long flags = ldv_undef_ulong();
	const char *name = ldv_undef_ptr();
	void *dev = ldv_undef_ptr();

	ldv_alloc(GFP_ATOMIC);
	ldv_alloc(GFP_NOWAIT);
	ldv_nonatomic_alloc();

	if (!request_irq(irq, ldv_handler, flags, name, dev))
		return ldv_undef_int_negative();

	ldv_nonatomic_alloc();
	ldv_alloc(GFP_NOWAIT);
	ldv_alloc(GFP_ATOMIC);

	return 0;
}

module_init(ldv_init);
