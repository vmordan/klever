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

#ifndef __LINUX_LDV_SLAB_H
#define __LINUX_LDV_SLAB_H

#include <linux/types.h>

extern void *ldv_kzalloc(size_t size, gfp_t flags);
extern void *ldv_kmalloc(size_t size, gfp_t flags);
extern void *ldv_kcalloc(size_t n, size_t size, gfp_t flags);
extern void *ldv_kmalloc_array(size_t n, size_t size, gfp_t flags);

extern void ldv_check_alloc_flags(gfp_t flags);
extern void ldv_after_alloc(void *res);

#endif /* __LINUX_LDV_SLAB_H */
