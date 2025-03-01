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

#include <linux/ldv/common.h>
#include <verifier/common.h>
#include <verifier/nondet.h>

void rtnl_lock(void);
void rtnl_unlock(void);

/* NOTE There is no rtnllock at the beginning */
int rtnllocknumber = 0;

/* MODEL_FUNC executed after rtnl_unlock */
void ldv_past_rtnl_unlock(void)
{
	/* ASSERT double rtnl_unlock */
	ldv_assert("linux:net:rtnetlink::double unlock", rtnllocknumber == 1);
	/* NOTE unlocking */
	rtnllocknumber=0;
}

/* MODEL_FUNC executed after rtnl_lock */
void ldv_past_rtnl_lock(void)
{
	/* ASSERT double rtnl_lock */
	ldv_assert("linux:net:rtnetlink::double lock", rtnllocknumber == 0);
	/* NOTE locking */
	rtnllocknumber=1;
}

/* MODEL_FUNC executed before ieee80211_unregister_hw */
void ldv_before_ieee80211_unregister_hw(void)
{
	/* NOTE Modeling lock */
	ldv_past_rtnl_lock();
	/* NOTE Modeling unlock */
	ldv_past_rtnl_unlock();
}

/* MODEL_FUNC rtnl is locked */
int ldv_rtnl_is_locked(void)
{
	/* NOTE If we know about lock */
	if (rtnllocknumber)
		/* NOTE rtnl_lock by this thread */
		return rtnllocknumber;
	/* NOTE If we dont know about lock */
	else if (ldv_undef_int())
		/* NOTE rtnl_lock by another thread */
		return 1;
	else 	
		/* NOTE There is no rtnl_lock */
		return 0;
}

/* MODEL_FUNC trylock */
int ldv_rtnl_trylock(void)
{
	/* ASSERT double rtnl_trylock */
	ldv_assert("linux:net:rtnetlink::double lock", rtnllocknumber == 0);
	/* NOTE If there is no rtnl_lock */
	if (!ldv_rtnl_is_locked()) { 
		/* NOTE locking by trylock */
		rtnllocknumber=1;
		/* NOTE Lock set */
		return 1;
	}
	/* NOTE Cant set lock */
	else return 0;
}

/* MODEL_FUNC check on exit */
void ldv_check_final_state(void)
{
	/* ASSERT lock_sock number */
	ldv_assert("linux:net:rtnetlink::lock on exit", rtnllocknumber == 0);
}
