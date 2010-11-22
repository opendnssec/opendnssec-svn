/*
 * $Id: worker.h 4089 2010-10-12 14:00:04Z matthijs $
 *
 * Copyright (c) 2009 NLNet Labs. All rights reserved.
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
 * The hard workers.
 *
 */

#ifndef DAEMON_WORKER_H
#define DAEMON_WORKER_H

#include "shared/allocator.h"
#include "shared/locks.h"

#include <time.h>


enum worker_enum {
    WORKER_NONE = 0,
    WORKER_WORKER = 1,
    WORKER_DRUDGER,
    WORKER_FETCHER
};
typedef enum worker_enum worker_id;

struct engine_struct;

typedef struct worker_struct worker_type;
struct worker_struct {
    int thread_num;
    ods_thread_type thread_id;
    struct engine_struct* engine;
    worker_id type;
    int sleeping;
    int waiting;
    int need_to_exit;
    cond_basic_type worker_alarm;
    lock_basic_type worker_lock;
};

/**
 * Create worker.
 * \param[in] allocator memory allocator
 * \param[in] num thread number
 * \param[in] type type of worker
 * \return worker_type* created worker
 *
 */
worker_type* worker_create(allocator_type* allocator, int num, worker_id type);

/**
 * Start working.
 * \param[in] worker worker to start working
 *
 */
void worker_start(worker_type* worker);

/**
 * Put worker to sleep.
 * \param[in] worker put this worker to sleep
 * \param[in] timeout time before alarm clock is going off,
 *            0 means no alarm clock is set.
 *
 */
void worker_sleep(worker_type* worker, time_t timeout);

/**
 * Let worker wait.
 * \param[in] worker waiting worker
 *
 */
void worker_wait(worker_type* worker);

/**
 * Wake up worker.
 * \param[in] worker wake up this worker
 *
 */
void worker_wakeup(worker_type* worker);

/**
 * Notify worker.
 * \param[in] worker notify this worker
 *
 */
void worker_notify(worker_type* worker);

#endif /* DAEMON_WORKER_H */
