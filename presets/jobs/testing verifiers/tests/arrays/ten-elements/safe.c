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
#include <verifier/common.h>
#include <verifier/nondet.h>

static int __init ldv_init(void)
{
	int var1 = ldv_undef_int(), var2 = ldv_undef_int(),
	    var3 = ldv_undef_int(), var4 = ldv_undef_int(),
	    var5 = ldv_undef_int(), var6 = ldv_undef_int(),
	    var7 = ldv_undef_int(), var8 = ldv_undef_int(),
	    var9 = ldv_undef_int(), var10 = ldv_undef_int(),
	    var11[10] = {var1, var2, var3, var4, var5, var6, var7, var8, var9,
	                 var10};

	if (var11[0] != var1)
		ldv_error();

	if (var11[1] != var2)
		ldv_error();

	if (var11[2] != var3)
		ldv_error();

	if (var11[3] != var4)
		ldv_error();

	if (var11[4] != var5)
		ldv_error();

	if (var11[5] != var6)
		ldv_error();

	if (var11[6] != var7)
		ldv_error();

	if (var11[7] != var8)
		ldv_error();

	if (var11[8] != var9)
		ldv_error();

	if (var11[9] != var10)
		ldv_error();

	return 0;
}

module_init(ldv_init);
