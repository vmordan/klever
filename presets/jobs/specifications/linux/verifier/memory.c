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

#include <linux/ldv/err.h>
#include <verifier/common.h>
#include <verifier/nondet.h>
#include <verifier/memory.h>

extern void *ldv_reference_malloc(size_t size);
extern void *ldv_reference_calloc(size_t nmemb, size_t size);
extern void *ldv_reference_zalloc(size_t size);
extern void ldv_reference_free(void *s);
extern void *ldv_reference_xmalloc(size_t size);
extern void *ldv_reference_xzalloc(size_t size);
extern void *ldv_reference_malloc_unknown_size(void);
extern void *ldv_reference_calloc_unknown_size(void);
extern void *ldv_reference_zalloc_unknown_size(void);
extern void *ldv_reference_xmalloc_unknown_size(size_t size);

void *ldv_malloc(size_t size)
{
    void *res;
    res = ldv_reference_malloc(size);
	if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_calloc(size_t nmemb, size_t size)
{
    void *res;
    res = ldv_reference_calloc(nmemb, size);
    if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_zalloc(size_t size)
{
	void *res;
    res = ldv_reference_zalloc(size);
    if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void ldv_free(void *s)
{
	ldv_reference_free(s);
}

void *ldv_xmalloc(size_t size)
{
    void *res;
    res = ldv_reference_xmalloc(size);
    ldv_assume(!ldv_is_err(res));
    return res;
}

void *ldv_xzalloc(size_t size)
{
	void *res;
	res = ldv_reference_xzalloc(size);
	ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_malloc_unknown_size(void)
{
    void *res;
    res = ldv_reference_malloc_unknown_size();
    if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_calloc_unknown_size(void)
{
	void *res;
    res = ldv_reference_calloc_unknown_size();
    if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_zalloc_unknown_size(void)
{
	void *res;
    res = ldv_reference_zalloc_unknown_size();
    if (res != NULL)
		ldv_assume(!ldv_is_err(res));
	return res;
}

void *ldv_xmalloc_unknown_size(size_t size)
{
    void *res;
	res = ldv_reference_xmalloc_unknown_size(size);
	ldv_assume(!ldv_is_err(res));
	return res;
}
