/*
 * $Id: worker.c 4089 2010-10-12 14:00:04Z matthijs $
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

#include "daemon/engine.h"
#include "daemon/worker.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/locks.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"

#include <time.h> /* time() */

ods_lookup_table worker_str[] = {
    { WORKER_WORKER, "worker" },
    { WORKER_DRUDGER, "drudger" },
    { WORKER_FETCHER, "fetcher" },
    { 0, NULL }
};


/**
 * Create worker.
 *
 */
worker_type*
worker_create(allocator_type* allocator, int num, worker_id type)
{
    worker_type* worker;
    ods_log_assert(allocator);

    worker = (worker_type*) allocator_alloc(allocator, sizeof(worker_type));
    if (!worker) {
        return NULL;
    }
    worker->thread_num = num +1;
    worker->engine = NULL;
    worker->need_to_exit = 0;
    worker->type = type;
    worker->sleeping = 0;
    worker->waiting = 0;
    lock_basic_init(&worker->worker_lock);
    lock_basic_set(&worker->worker_alarm);
    return worker;
}

/**
 * Convert worker type to string.
 *
 */
static const char*
worker2str(worker_id type)
{
    ods_lookup_table *lt = ods_lookup_by_id(worker_str, type);
    if (lt) {
        return lt->name;
    }
    return NULL;
}


/**
 * Work.
 *
 */
static void
worker_work(worker_type* worker)
{
    time_t now, timeout = 1;
    zone_type* zone = NULL;
    task_type* task = NULL;
    ods_status status;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_WORKER);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]]: report for duty", worker2str(worker->type),
            worker->thread_num);
        lock_basic_lock(&worker->engine->taskq->schedule_lock);
        /* [LOCK] schedule */
        task = schedule_pop_task(worker->engine->taskq);
        /* [UNLOCK] schedule */
        if (task) {
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);

            zone = task->zone;
            lock_basic_lock(&zone->zone_lock);
            /* [LOCK] zone */
            ods_log_debug("[%s[%i]] start working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            sleep(50);
            ods_log_debug("[%s[%i]] finished working on zone %s",
                worker2str(worker->type), worker->thread_num, zone->name);
            task->when = time_now() + 3600;
            zone->task = task;
            task = NULL;
            /* [UNLOCK] zone */

            lock_basic_lock(&worker->engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            status = schedule_add_task(worker->engine->taskq, zone->task, 1);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);
            lock_basic_unlock(&zone->zone_lock);

            timeout = 1;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);

            /* [LOCK] schedule */
            task = schedule_get_first_task(worker->engine->taskq);
            /* [UNLOCK] schedule */
            lock_basic_unlock(&worker->engine->taskq->schedule_lock);

            now = time_now();
            if (task && !worker->engine->taskq->loading) {
                timeout = (task->when - now);
            } else {
                timeout *= 2;
                if (timeout > ODS_SE_MAX_BACKOFF) {
                    timeout = ODS_SE_MAX_BACKOFF;
                }
            }
            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Drudge.
 *
 */
static void
worker_drudge(worker_type* worker)
{
    time_t now, timeout = 1;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_DRUDGER);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]]: report for duty", worker2str(worker->type),
            worker->thread_num);

        if (0) {
            timeout = 1;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);
            timeout = ODS_SE_MAX_BACKOFF;
            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Fetch boy!.
 *
 */
static void
worker_fetch(worker_type* worker)
{
    time_t now, timeout = 1;

    ods_log_assert(worker);
    ods_log_assert(worker->type == WORKER_FETCHER);

    while (worker->need_to_exit == 0) {
        ods_log_debug("[%s[%i]]: report for duty", worker2str(worker->type),
            worker->thread_num);

        if (0) {
            timeout = 1;
        } else {
            ods_log_debug("[%s[%i]] nothing to do", worker2str(worker->type),
                worker->thread_num);
            timeout = ODS_SE_MAX_BACKOFF;
            worker_sleep(worker, timeout);
        }
    }
    return;
}


/**
 * Start worker.
 *
 */
void
worker_start(worker_type* worker)
{
    ods_log_assert(worker);
    switch (worker->type) {
        case WORKER_FETCHER:
            worker_fetch(worker);
            break;
        case WORKER_DRUDGER:
            worker_drudge(worker);
            break;
        case WORKER_WORKER:
            worker_work(worker);
            break;
        default:
            ods_log_error("[worker] illegal worker (id=%i)", worker->type);
            return;
    }
    return;
}


/**
 * Put worker to sleep.
 *
 */
void
worker_sleep(worker_type* worker, time_t timeout)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    /* [LOCK] worker */
    worker->sleeping = 1;
    lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock,
        timeout);
    /* [UNLOCK] worker */
    lock_basic_unlock(&worker->worker_lock);
    return;
}


/**
 * Worker waiting.
 *
 */
void
worker_wait(worker_type* worker)
{
    ods_log_assert(worker);
    lock_basic_lock(&worker->worker_lock);
    /* [LOCK] worker */
    worker->waiting = 1;
    lock_basic_sleep(&worker->worker_alarm, &worker->worker_lock, 0);
    /* [UNLOCK] worker */
    lock_basic_unlock(&worker->worker_lock);
    return;
}


/**
 * Wake up worker.
 *
 */
void
worker_wakeup(worker_type* worker)
{
    ods_log_assert(worker);
    if (worker && worker->sleeping && !worker->waiting) {
        ods_log_debug("[%s[%i]] wake up", worker2str(worker->type),
           worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        /* [LOCK] worker */
        lock_basic_alarm(&worker->worker_alarm);
        worker->sleeping = 0;
        /* [UNLOCK] worker */
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}


/**
 * Notify worker.
 *
 */
void
worker_notify(worker_type* worker)
{
    ods_log_assert(worker);
    if (worker && worker->waiting && !worker->sleeping) {
        ods_log_debug("[%s[%i]] notify", worker2str(worker->type),
           worker->thread_num);
        lock_basic_lock(&worker->worker_lock);
        /* [LOCK] worker */
        lock_basic_alarm(&worker->worker_alarm);
        worker->waiting = 0;
        /* [UNLOCK] worker */
        lock_basic_unlock(&worker->worker_lock);
    }
    return;
}
