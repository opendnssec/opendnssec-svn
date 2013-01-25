/*
 * $Id$
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * FIFO Queue.
 *
 */

#include "config.h"
#include "daemon/worker.h"
#include "scheduler/fifoq.h"
#include "shared/allocator.h"
#include "shared/log.h"

#include <ldns/ldns.h>

static const char* fifoq_str = "fifo";


/**
 * Create new FIFO queue.
 *
 */
fifoq_type*
fifoq_create(allocator_type* allocator)
{
    fifoq_type* fifoq;
    if (!allocator) {
        ods_log_error("[%s] unable to create: no allocator available",
            fifoq_str);
        return NULL;
    }
    ods_log_assert(allocator);

    fifoq = (fifoq_type*) allocator_alloc(allocator, sizeof(fifoq_type));
    if (!fifoq) {
        ods_log_error("[%s] unable to create: allocator failed", fifoq_str);
        return NULL;
    }
    ods_log_assert(fifoq);

    fifoq->allocator = allocator;
    fifoq_wipe(fifoq);
    lock_basic_init(&fifoq->q_lock);
    lock_basic_set(&fifoq->q_threshold);
    lock_basic_set(&fifoq->q_nonfull);
    return fifoq;
}


/**
 * Wipe queue.
 *
 */
void
fifoq_wipe(fifoq_type* q)
{
    size_t i = 0;

    for (i=0; i < FIFOQ_MAX_COUNT; i++) {
        q->blob[i] = NULL;
        q->owner[i] = NULL;
    }
    q->count = 0;
    return;
}


/**
 * Pop item from queue.
 *
 */
void*
fifoq_pop(fifoq_type* q, worker_type** worker)
{
    void* pop = NULL;
    size_t i = 0;

    if (!q) {
        return NULL;
    }
    if (q->count <= 0) {
        return NULL;
    }

    pop = q->blob[0];
    *worker = q->owner[0];
    for (i = 0; i < q->count-1; i++) {
        q->blob[i] = q->blob[i+1];
        q->owner[i] = q->owner[i+1];
    }
    q->count -= 1;

    if (q->count <= (size_t) FIFOQ_MAX_COUNT * 0.1) {
        /* notify waiting workers that they can start queuing again */
        lock_basic_broadcast(&q->q_nonfull);
    }
    return pop;
}


/**
 * Push item to queue.
 *
 */
ods_status
fifoq_push(fifoq_type* q, void* item, worker_type* worker, int* tries)
{
    ods_log_assert(q);
    ods_log_assert(item);
    ods_log_assert(worker);

    if (q->count >= FIFOQ_MAX_COUNT) {
        /* #262 if drudgers remain on hold, do additional broadcast */
        if (*tries > FIFOQ_TRIES_COUNT) {
            lock_basic_broadcast(&q->q_threshold);
            ods_log_debug("[%s] queue full, notify drudgers again", fifoq_str);
            /* reset tries */
            *tries = 0;
        }
        return ODS_STATUS_UNCHANGED;
    }

    q->blob[q->count] = item;
    q->owner[q->count] = worker;
    q->count += 1;
    if (q->count == 1) {
        lock_basic_broadcast(&q->q_threshold);
        ods_log_deeebug("[%s] threshold %u reached, notify drudgers",
            fifoq_str, q->count);
    }
    return ODS_STATUS_OK;
}


/**
 * Clean up queue.
 *
 */
void
fifoq_cleanup(fifoq_type* q)
{
    allocator_type* allocator;
    lock_basic_type q_lock;
    cond_basic_type q_threshold;
    cond_basic_type q_nonfull;

    if (!q) {
        return;
    }
    ods_log_assert(q);
    allocator = q->allocator;
    q_lock = q->q_lock;
    q_threshold = q->q_threshold;
    q_nonfull = q->q_nonfull;

    allocator_deallocate(allocator, (void*) q);
    lock_basic_off(&q_threshold);
    lock_basic_off(&q_nonfull);
    lock_basic_destroy(&q_lock);
    return;
}
