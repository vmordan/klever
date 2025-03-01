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
#include <linux/seq_file.h>
#include <linux/emg/test_model.h>
#include <verifier/nondet.h>

struct file *file;
struct inode *inode;

static void *ldv_start_callback(struct seq_file *file, loff_t *pos)
{
	ldv_invoke_reached();
	return 0;
}

static void ldv_stop_callback(struct seq_file *file, void *iter_ptr)
{
	ldv_invoke_reached();
}

static const struct seq_operations ldv_ops = {
	.start = ldv_start_callback,
	.stop  = ldv_stop_callback,
};

static int __init ldv_init(void)
{
	ldv_invoke_test();
	return seq_open(file, &ldv_ops);
}

static void __exit ldv_exit(void)
{
	seq_release(inode,file);
}

module_init(ldv_init);
module_exit(ldv_exit);
