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
#include <linux/sysfs.h>
#include <verifier/common.h>
#include <verifier/nondet.h>

static struct attribute *attrs[] = {
	NULL,
};

static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int __init ldv_init(void)
{
	struct kobject *kobj = ldv_undef_ptr();

	ldv_assume(!sysfs_create_group(kobj, &attr_group));

	return 0;
}

module_init(ldv_init);
