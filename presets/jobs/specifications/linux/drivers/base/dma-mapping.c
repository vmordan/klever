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

#include <linux/types.h>
#include <linux/ldv/common.h>
#include <verifier/common.h>
#include <verifier/nondet.h>

int ldv_dma_calls = 0;

/* MODEL_FUNC Map page */
dma_addr_t ldv_dma_map_page(void) {
	/* ASSERT Check that previous dma_mapping call was checked */
	ldv_assert("linux:drivers:base:dma-mapping::unchecked", ldv_dma_calls == 0);
	/* NOTE Increase map counter */
	ldv_dma_calls++;

	return ldv_undef_int();
}

/* MODEL_FUNC Check page */
int ldv_dma_mapping_error(void) {
	/* ASSERT No dma_mapping calls to verify */				
	ldv_assert("linux:drivers:base:dma-mapping::check before map", ldv_dma_calls > 0);
	ldv_dma_calls--;

	return ldv_undef_int();
}

/* MODEL_FUNC Map page */
dma_addr_t ldv_dma_map_single(void) {
	/* ASSERT Check that previous dma_mapping call was checked */
	ldv_assert("linux:drivers:base:dma-mapping::unchecked", ldv_dma_calls == 0);
	/* NOTE Increase map counter */
	ldv_dma_calls++;

	return ldv_undef_int();
}
	
/* MODEL_FUNC Map page */
dma_addr_t ldv_dma_map_single_attrs(void) {
	/* ASSERT Check that previous dma_mapping call was checked */
	ldv_assert("linux:drivers:base:dma-mapping::unchecked", ldv_dma_calls == 0);
	/* NOTE Increase map counter */
	ldv_dma_calls++;

	return ldv_undef_int();
}

/* MODEL_FUNC Check that all dma_mapping calls are checked at the end */
void ldv_check_final_state(void) {
	/* ASSERT All dma_mapping calls should be checked before module unloading */
	ldv_assert("linux:drivers:base:dma-mapping::unchecked at exit", ldv_dma_calls == 0);
}
