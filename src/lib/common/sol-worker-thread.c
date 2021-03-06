/*
 * This file is part of the Soletta Project
 *
 * Copyright (C) 2015 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>
#include <stdlib.h>

#include "sol-util.h"
#include "sol-macros.h"
#include "sol-worker-thread.h"
#include "sol-worker-thread-impl.h"

SOL_LOG_INTERNAL_DECLARE(_sol_worker_thread_log_domain, "worker-thread");

SOL_API struct sol_worker_thread *
sol_worker_thread_new(const struct sol_worker_thread_spec *spec)
{
    SOL_NULL_CHECK(spec, NULL);
    SOL_NULL_CHECK(spec->iterate, NULL);

#ifndef SOL_NO_API_VERSION
    if (unlikely(spec->api_version != SOL_WORKER_THREAD_SPEC_API_VERSION)) {
        SOL_WRN("Couldn't create worker thread with unsupported version '%u', "
            "expected version is '%u'",
            spec->api_version, SOL_WORKER_THREAD_SPEC_API_VERSION);
        return NULL;
    }
#endif

    return sol_worker_thread_impl_new(spec);
}

SOL_API void
sol_worker_thread_cancel(struct sol_worker_thread *thread)
{
    SOL_NULL_CHECK(thread);
    sol_worker_thread_impl_cancel(thread);
}

SOL_API bool
sol_worker_thread_cancel_check(const struct sol_worker_thread *thread)
{
    SOL_NULL_CHECK(thread, false);
    return sol_worker_thread_impl_cancel_check(thread);
}

SOL_API void
sol_worker_thread_feedback(struct sol_worker_thread *thread)
{
    SOL_NULL_CHECK(thread);
    sol_worker_thread_impl_feedback(thread);
}
