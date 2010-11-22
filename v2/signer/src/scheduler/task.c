/*
 * $Id$
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
 * Tasks.
 *
 */

#include "config.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/duration.h"
#include "shared/locks.h"
#include "shared/log.h"

static const char* task_str = "task";


/**
 * Create a new task.
 *
 */
task_type*
task_create(task_id what, time_t when, const char* who, void* zone)
{
    allocator_type* allocator = NULL;
    task_type* task = NULL;

    if (!who || !zone) {
        ods_log_error("[%s] cannot create: missing zone info", task_str);
        return NULL;
    }
    ods_log_assert(who);
    ods_log_assert(zone);

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] cannot create: create allocator failed", task_str);
        return NULL;
    }
    ods_log_assert(allocator);

    task = (task_type*) allocator_alloc(allocator, sizeof(task_type));
    if (!task) {
        allocator_cleanup(allocator);
        return NULL;
    }
    task->allocator = allocator;
    task->what = what;
    task->when = when;
    task->backoff = 0;
    task->who = allocator_strdup(allocator, who);
    task->dname = ldns_dname_new_frm_str(who);
    task->flush = 0;
    task->zone = zone;
    return task;
}


/**
 * Clean up task.
 *
 */
void
task_cleanup(task_type* task)
{
    allocator_type* allocator;

    if (task) {
        allocator = task->allocator;
        if (task->dname) {
            ldns_rdf_deep_free(task->dname);
            task->dname = NULL;
        }
        allocator_deallocate(allocator);
        allocator_cleanup(allocator);
    }
    return;
}


/**
 * Compare tasks.
 *
 */
int
task_compare(const void* a, const void* b)
{
    task_type* x = (task_type*)a;
    task_type* y = (task_type*)b;

    ods_log_assert(x);
    ods_log_assert(y);

    if (!ldns_dname_compare((const void*) x->dname, (const void*) y->dname)) {
        return 0;
    }

    if (x->when != y->when) {
        return (int) x->when - y->when;
    }
    return ldns_dname_compare((const void*) x->dname, (const void*) y->dname);
}


/**
 * Convert task to string.
 *
 */
char*
task2str(task_type* task, char* buftask)
{
    time_t now = time_now();
    char* strtime = NULL;
    char* strtask = NULL;

    if (task) {
        if (task->flush) {
            strtime = ctime(&now);
        } else {
            strtime = ctime(&task->when);
        }
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        if (buftask) {
            (void)snprintf(buftask, ODS_SE_MAXLINE, "On %s I will %s zone %s"
                "\n", strtime?strtime:"(null)", task_what2str(task->what),
                task_who2str(task->who));
            return buftask;
        } else {
            strtask = (char*) calloc(ODS_SE_MAXLINE, sizeof(char));
            snprintf(strtask, ODS_SE_MAXLINE, "On %s I will %s zone %s\n",
                strtime?strtime:"(null)", task_what2str(task->what),
                task_who2str(task->who));
            return strtask;
        }
    }
    return NULL;
}


/**
 * String-format of what.
 *
 */
const char*
task_what2str(int what)
{
    switch (what) {
        case TASK_NONE:
            return "do nothing with";
            break;
        case TASK_READ:
            return "read and sign";
            break;
        case TASK_ADDKEYS:
            return "add keys and sign";
            break;
        case TASK_UPDATE:
            return "prepare and sign";
            break;
        case TASK_NSECIFY:
            return "nsecify and sign";
            break;
        case TASK_SIGN:
            return "sign";
            break;
        case TASK_AUDIT:
            return "audit";
            break;
        case TASK_WRITE:
            return "output signed";
            break;
        default:
            return "???";
            break;
    }

    return "???";
}

/**
 * String-format of who.
 *
 */
const char*
task_who2str(const char* who)
{
    if (who) {
        return who;
    }
    return "(null)";
}


/**
 * Print task.
 *
 */
void
task_print(FILE* out, task_type* task)
{
    time_t now = time_now();
    char* strtime = NULL;

    if (out && task) {
        if (task->flush) {
            strtime = ctime(&now);
        } else {
            strtime = ctime(&task->when);
        }
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        fprintf(out, "On %s I will %s zone %s\n", strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task->who));
    }
    return;
}

/**
 * Log task.
 *
 */
void
task_log(task_type* task)
{
    time_t now = time_now();
    char* strtime = NULL;

    if (task) {
        if (task->flush) {
            strtime = ctime(&now);
        } else {
            strtime = ctime(&task->when);
        }
        if (strtime) {
            strtime[strlen(strtime)-1] = '\0';
        }
        ods_log_debug("[%s] On %s I will %s zone %s", task_str,
            strtime?strtime:"(null)",
            task_what2str(task->what), task_who2str(task->who));
    }
    return;
}
