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

#include <verifier/common.h>
#include <verifier/memory.h>
#include <verifier/nondet.h>

int ldv_asprintf(char **ptr);

int ldv_asprintf(char **ptr)
{
    char *new;
    if (ldv_undef_int()) {
        new = (char *) ldv_xmalloc_unknown_size(sizeof(char));
        *ptr = new;
        return ldv_undef_int_positive();
    } else {
        return -1;
    }
}
