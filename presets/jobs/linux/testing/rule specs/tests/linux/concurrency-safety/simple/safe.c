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
#include <linux/mutex.h>
#include <verifier/nondet.h>
#include <verifier/thread.h>

static DEFINE_MUTEX(ldv_lock);
static int _ldv_global_var;

static void *ldv_func1(void *arg)
{
	mutex_lock(&ldv_lock);
	_ldv_global_var = 1;
	mutex_unlock(&ldv_lock);

	return NULL;
}

static void *ldv_func2(void *arg)
{
	int var;

	mutex_lock(&ldv_lock);
	var = _ldv_global_var;
	mutex_unlock(&ldv_lock);

	return NULL;
}

static int __init ldv_init(void)
{
	pthread_t thread1, thread2;
	pthread_attr_t const *attr1 = ldv_undef_ptr(), *attr2 = ldv_undef_ptr();
	void *arg1 = ldv_undef_ptr(), *arg2 = ldv_undef_ptr();

	pthread_create(&thread1, attr1, &ldv_func1, arg1);
	pthread_create(&thread2, attr2, &ldv_func2, arg2);

	return 0;
}

module_init(ldv_init);
