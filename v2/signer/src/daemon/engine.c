/*
 * $Id: engine.c 4138 2010-10-25 12:59:43Z matthijs $
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
 * The engine.
 *
 */

#include "config.h"
#include "daemon/cfg.h"
#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "daemon/worker.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"
#include "shared/privdrop.h"
#include "shared/status.h"
#include "shared/util.h"

#include <errno.h>
#include <libhsm.h>
#include <libxml/parser.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>


static const char* engine_str = "engine";


/**
 * Create engine.
 *
 */
static engine_type*
engine_create(void)
{
    engine_type* engine;
    allocator_type* allocator = allocator_create(malloc, free);

    if (!allocator) {
        return NULL;
    }
    engine = (engine_type*) allocator_alloc(allocator, sizeof(engine_type));
    if (!engine) {
        allocator->deallocator(allocator);
        return NULL;
    }
    engine->allocator = allocator;
    engine->workers = NULL;
    engine->drudgers = NULL;
    engine->fetchers = NULL;
    engine->zonelist = NULL;
    engine->zonelist = zonelist_create(engine->allocator);
    engine->taskq = schedule_create(engine->allocator);
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;

    engine->pid = -1;
    engine->zfpid = -1;
    engine->uid = -1;
    engine->gid = -1;

    engine->daemonize = 0;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;

    engine->signal = SIGNAL_INIT;
    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);
    return engine;
}


/**
 * Drop privileges.
 *
 */
static ods_status
engine_privdrop(engine_type* engine)
{
    ods_status status = ODS_STATUS_OK;
    uid_t uid = -1;
    gid_t gid = -1;

    ods_log_assert(engine);
    ods_log_assert(engine->config);

    if (engine->config->username && engine->config->group) {
        ods_log_verbose("[%s] drop privileges to user %s, group %s",
           engine_str, engine->config->username, engine->config->group);
    } else if (engine->config->username) {
        ods_log_verbose("[%s] drop privileges to user %s", engine_str,
           engine->config->username);
    } else if (engine->config->group) {
        ods_log_verbose("[%s] drop privileges to group %s", engine_str,
           engine->config->group);
    }
    if (engine->config->chroot) {
        ods_log_verbose("[%s] chroot to %s", engine_str,
            engine->config->chroot);
    }
    status = privdrop(engine->config->username, engine->config->group,
        engine->config->chroot, &uid, &gid);
    engine->uid = uid;
    engine->gid = gid;
    privclose(engine->config->username, engine->config->group);
    return status;
}


/**
 * Start/stop command handler.
 *
 */
static void*
cmdhandler_thread_start(void* arg)
{
    cmdhandler_type* cmdh = (cmdhandler_type*) arg;
    ods_thread_blocksigs();
    cmdhandler_start(cmdh);
    return NULL;
}
static void
engine_start_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    ods_log_debug("[%s] start command handler", engine_str);
    engine->cmdhandler->engine = engine;
    ods_thread_create(&engine->cmdhandler->thread_id,
        cmdhandler_thread_start, engine->cmdhandler);
    return;
}
static int
self_pipe_trick(engine_type* engine)
{
    int sockfd, ret;
    struct sockaddr_un servaddr;
    const char* servsock_filename = ODS_SE_SOCKFILE;

    ods_log_assert(engine);
    ods_log_assert(engine->cmdhandler);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd <= 0) {
        ods_log_error("[%s] cannot connect to command handler: "
            "socket() failed: %s\n", engine_str, strerror(errno));
        return 1;
    } else {
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sun_family = AF_UNIX;
        strncpy(servaddr.sun_path, servsock_filename,
            sizeof(servaddr.sun_path) - 1);

        ret = connect(sockfd, (const struct sockaddr*) &servaddr,
            sizeof(servaddr));
        if (ret != 0) {
            ods_log_error("[%s] cannot connect to command handler: "
                "connect() failed: %s\n", engine_str, strerror(errno));
            close(sockfd);
            return 1;
        } else {
            /* self-pipe trick */
            ods_writen(sockfd, "", 1);
            close(sockfd);
        }
    }
    return 0;
}
static void
engine_stop_cmdhandler(engine_type* engine)
{
    ods_log_assert(engine);
    if (!engine->cmdhandler) {
        return;
    }
    ods_log_debug("[%s] stop command handler", engine_str);
    engine->cmdhandler->need_to_exit = 1;
    if (self_pipe_trick(engine) == 0) {
        while (!engine->cmdhandler_done) {
            ods_log_debug("[%s] waiting for command handler to exit...",
                engine_str);
            sleep(1);
        }
    } else {
        ods_log_error("[%s] command handler self pipe trick failed, "
            "unclean shutdown", engine_str);
    }
    return;
}


/**
 * Start/stop workers.
 *
 */
static void
engine_create_workers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->allocator);
    engine->workers = (worker_type**) allocator_alloc(engine->allocator,
        ((size_t)engine->config->num_worker_threads) * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i] = worker_create(engine->allocator, i, WORKER_WORKER);
    }
    return;
}
static void
engine_create_drudgers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->allocator);
    engine->drudgers = (worker_type**) allocator_alloc(engine->allocator,
        ((size_t)engine->config->num_signer_threads) * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i] = worker_create(engine->allocator, i, WORKER_DRUDGER);
    }
    return;
}
static void
engine_create_fetchers(engine_type* engine)
{
    size_t i = 0;
    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_assert(engine->allocator);
    engine->fetchers = (worker_type**) allocator_alloc(engine->allocator,
        ((size_t)engine->config->num_fetcher_threads) * sizeof(worker_type*));
    for (i=0; i < (size_t) engine->config->num_fetcher_threads; i++) {
        engine->fetchers[i] = worker_create(engine->allocator, i, WORKER_FETCHER);
    }
    return;
}
static void*
worker_thread_start(void* arg)
{
    worker_type* worker = (worker_type*) arg;
    ods_thread_blocksigs();
    worker_start(worker);
    return NULL;
}
static void
engine_start_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start workers", engine_str);
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 0;
        engine->workers[i]->engine = (struct engine_struct*) engine;
        ods_thread_create(&engine->workers[i]->thread_id, worker_thread_start,
            engine->workers[i]);
    }
    return;
}
static void
engine_start_drudgers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start drudgers", engine_str);
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 0;
        engine->drudgers[i]->engine = (struct engine_struct*) engine;
        ods_thread_create(&engine->drudgers[i]->thread_id, worker_thread_start,
            engine->drudgers[i]);
    }
    return;
}
static void
engine_start_fetchers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] start fetchers", engine_str);
    for (i=0; i < (size_t) engine->config->num_fetcher_threads; i++) {
        engine->fetchers[i]->need_to_exit = 0;
        engine->fetchers[i]->engine = (struct engine_struct*) engine;
        ods_thread_create(&engine->fetchers[i]->thread_id, worker_thread_start,
            engine->fetchers[i]);
    }
    return;
}
static void
engine_stop_workers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop workers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        engine->workers[i]->need_to_exit = 1;
        worker_wakeup(engine->workers[i]);
    }
    /* head count */
    for (i=0; i < (size_t) engine->config->num_worker_threads; i++) {
        ods_log_debug("[%s] join worker %i", engine_str, i+1);
        ods_thread_join(engine->workers[i]->thread_id);
        engine->workers[i]->engine = NULL;
    }
    return;
}
static void
engine_stop_drudgers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop drudgers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        engine->drudgers[i]->need_to_exit = 1;
        worker_wakeup(engine->drudgers[i]);
    }
    /* head count */
    for (i=0; i < (size_t) engine->config->num_signer_threads; i++) {
        ods_log_debug("[%s] join drudger %i", engine_str, i+1);
        ods_thread_join(engine->drudgers[i]->thread_id);
        engine->drudgers[i]->engine = NULL;
    }
    return;
}
static void
engine_stop_fetchers(engine_type* engine)
{
    size_t i = 0;

    ods_log_assert(engine);
    ods_log_assert(engine->config);
    ods_log_debug("[%s] stop fetchers", engine_str);
    /* tell them to exit and wake up sleepyheads */
    for (i=0; i < (size_t) engine->config->num_fetcher_threads; i++) {
        ods_log_debug("[%s] join fetcher %i", engine_str, i+1);
        engine->fetchers[i]->need_to_exit = 1;
        worker_wakeup(engine->fetchers[i]);
    }
    /* head count */
    for (i=0; i < (size_t) engine->config->num_fetcher_threads; i++) {
        ods_thread_join(engine->fetchers[i]->thread_id);
        engine->fetchers[i]->engine = NULL;
    }
    return;
}


/**
 * Update zones signer configurations.
 *
 */
void
engine_update_zones(engine_type* engine, int* unc, int* upd, int* err)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;
    zone_type* delzone = NULL;
    task_type* task = NULL;
    ods_status status;
    time_t now = 0;
    task_id what = TASK_NONE;
    int unchanged = 0;
    int errors = 0;
    int updated = 0;

    if (!engine || !engine->zonelist || !engine->zonelist->zones) {
        ods_log_error("[%s] cannot update zones: no engine or zonelist",
            engine_str);
        goto update_zones_exit;
    }
    ods_log_assert(engine);
    ods_log_assert(engine->zonelist);
    ods_log_assert(engine->zonelist->zones);

    /* [LOCK] zonelist */
    lock_basic_lock(&engine->zonelist->zl_lock);
    node = ldns_rbtree_first(engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->key;

        lock_basic_lock(&zone->zone_lock);
        if (zone->tobe_removed) {
            node = ldns_rbtree_next(node);
            delzone = zonelist_del_zone(engine->zonelist, zone);
            if (delzone) {
                lock_basic_lock(&engine->taskq->schedule_lock);
                /* [LOCK] zonelist, zone, schedule */
                task = schedule_del_task(engine->taskq,
                    (task_type*) zone->task);
                /* [UNLOCK] zonelist, zone, schedule */
                lock_basic_unlock(&engine->taskq->schedule_lock);
            }
            task_cleanup(task);
            task = NULL;

            lock_basic_unlock(&zone->zone_lock);
            zone_cleanup(zone);
            zone = NULL;
            continue;
        }

        /* [LOCK] zone */
        status = zone_load_signconf(zone, &what);
        if (status == ODS_STATUS_OK) {
            task = (task_type*) zone->task;
            lock_basic_lock(&engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            zone->task = schedule_del_task(engine->taskq, task);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&engine->taskq->schedule_lock);

            now = time_now();
            if (!zone->task) {
                task = task_create(TASK_READ, now, zone->name, zone);
            } else {
                task = zone->task;
                task->what = what;
                task->when = now;
            }
            zone->task = task;

            lock_basic_lock(&engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            status = schedule_add_task(engine->taskq, zone->task, 0);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&engine->taskq->schedule_lock);

            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] cannot schedule task for zone %s: %s",
                    engine_str, zone->name, ods_status2str(status));
                task_cleanup(task);
                zone->task = NULL;
            }
            updated++;
        } else if (status == ODS_STATUS_UNCHANGED) {
            unchanged++;
        } else {
            errors++;
        }
        zone->just_added = 0;
        zone->just_updated = 0;
        /* [UNLOCK] zone */
        lock_basic_unlock(&zone->zone_lock);

        node = ldns_rbtree_next(node);
    }
    lock_basic_unlock(&engine->zonelist->zl_lock);
    /* [UNLOCK] zonelist */

update_zones_exit:
    if (unc) {
        *unc = unchanged;
    }
    if (upd) {
        *upd = updated;
    }
    if (err) {
        *err = errors;
    }
    return;
}


/**
 * Set up engine.
 *
 */
static ods_status
engine_setup(engine_type* engine)
{
    struct sigaction action;

    ods_log_debug("[%s] signer setup", engine_str);
    if (!engine || !engine->config) {
        return ODS_STATUS_ASSERT_ERR;
    }

    /* pre setup */
    engine->cmdhandler = cmdhandler_create(engine->allocator,
        engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        ods_log_error("[%s] create command handler to %s failed",
            engine_str, engine->config->clisock_filename);
        return ODS_STATUS_CMDHANDLER_ERR;
    }

    /* privdrop */
    ods_chown(engine->config->clisock_filename, engine->uid, engine->gid, 0);
    ods_chown(engine->config->working_dir, engine->uid, engine->gid, 0);
    if (engine->config->log_filename && !engine->config->use_syslog) {
        ods_chown(engine->config->log_filename, engine->uid, engine->gid, 0);
    }
    if (engine->config->working_dir &&
        chdir(engine->config->working_dir) != 0) {
        ods_log_error("[%s] chdir to %s failed: %s", engine_str,
            engine->config->working_dir, strerror(errno));
        return ODS_STATUS_CHDIR_ERR;
    }
    if (engine_privdrop(engine) != ODS_STATUS_OK) {
        return ODS_STATUS_PRIVDROP_ERR;
    }

    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                ods_log_error("[%s] unable to fork daemon: %s", engine_str,
                    strerror(errno));
                return ODS_STATUS_FORK_ERR;
            case 0: /* child */
                break;
            default: /* parent */
                engine_cleanup(engine);
                xmlCleanupParser();
                xmlCleanupGlobals();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            ods_log_error("[%s] unable to setsid daemon (%s)", engine_str,
                strerror(errno));
            return ODS_STATUS_SETSID_ERR;
        }
    }
    engine->pid = getpid();
    ods_log_verbose("[%s] running as pid %lu", engine_str,
        (unsigned long) engine->pid);

    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    /* set up hsm */
/*    result = hsm_open(engine->config->cfg_filename, hsm_prompt_pin,
        NULL); */ /* LEAK */
/*
    if (result != HSM_OK) {
        ods_log_error("[%s] error initializing libhsm (errno %i)",
            engine_str, result);
        return ODS_STATUS_HSM_ERR;
    }
*/
    /* start command handler */
    engine_start_cmdhandler(engine);

    /* write pidfile */
    if (util_write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
/*        hsm_close(); */
        return ODS_STATUS_WRITE_PIDFILE_ERR;
    }

    /* post setup */
    engine_create_workers(engine);
    engine_create_drudgers(engine);
    engine_create_fetchers(engine);

    return 0;
}


/**
 * Run engine, run!.
 *
 */
static void
engine_run(engine_type* engine, int single_run)
{
    ods_log_assert(engine);

    engine_start_workers(engine);

    lock_basic_lock(&engine->signal_lock);
    /* [LOCK] signal */
    engine->signal = SIGNAL_RUN;
    /* [UNLOCK] signal */
    lock_basic_unlock(&engine->signal_lock);

    while (!engine->need_to_exit && !engine->need_to_reload) {
        lock_basic_lock(&engine->signal_lock);
        /* [LOCK] signal */
        engine->signal = signal_capture(engine->signal);
        switch (engine->signal) {
            case SIGNAL_RUN:
                ods_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                ods_log_warning("[%s] invalid signal captured: %d, "
                    "keep running", engine_str, signal);
                engine->signal = SIGNAL_RUN;
                break;
        }
        /* [UNLOCK] signal */
        lock_basic_unlock(&engine->signal_lock);

        if (single_run) {
           engine->need_to_exit = 1; /* engine_all_zones_processed(engine); */
        }

        lock_basic_lock(&engine->signal_lock);
        /* [LOCK] signal */
        if (engine->signal == SIGNAL_RUN && !single_run) {
           ods_log_debug("[%s] taking a break", engine_str);
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        /* [UNLOCK] signal */
        lock_basic_unlock(&engine->signal_lock);
    }

    ods_log_debug("[%s] signer halted", engine_str);
    engine_stop_workers(engine);
    return;
}


/**
 * Start engine.
 *
 */
void
engine_start(const char* cfgfile, int cmdline_verbosity, int daemonize,
    int info, int single_run)
{
    engine_type* engine;
    int use_syslog = 0;
    int updated = 0;
    int errors = 0;
    int unchanged = 0;
    ods_status zl_changed = ODS_STATUS_UNCHANGED;
    ods_status status = ODS_STATUS_OK;

    ods_log_init(NULL, use_syslog, cmdline_verbosity);
    ods_log_verbose("[%s] starting signer", engine_str);

    /* initialize */
    xmlInitGlobals();
    xmlInitParser();
    engine = engine_create();
    if (!engine) {
        ods_fatal_exit("[%s] create failed", engine_str);
        return;
    }
    engine->daemonize = daemonize;

    /* config */
    engine->config = engine_config(engine->allocator, cfgfile,
        cmdline_verbosity);
    status = engine_config_check(engine->config);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] cfgfile %s has errors", engine_str, cfgfile);
        goto earlyexit;
    }
    if (info) {
        engine_config_print(stdout, engine->config);
        goto earlyexit;
    }

    /* open log */
/*
    ods_log_init(engine->config->log_filename, engine->config->use_syslog,
        engine->config->verbosity);
*/

    /* setup */
    tzset(); /* for portability */
    status = engine_setup(engine);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] setup failed: %s", engine_str,
            ods_status2str(status));
        engine->need_to_exit = 1;
        if (status != ODS_STATUS_WRITE_PIDFILE_ERR) {
            /* command handler had not yet been started */
            engine->cmdhandler_done = 1;
        }
    }

    /* run */
    while (engine->need_to_exit == 0) {
        if (engine->need_to_reload) {
            ods_log_info("[%s] signer reloading", engine_str);
            engine->need_to_reload = 0;
        } else {
            ods_log_info("[%s] signer started", engine_str);
            /* try to recover from backups */
        }

        /* update zone list */
        lock_basic_lock(&engine->zonelist->zl_lock);
        /* [LOCK] zonelist */
        zl_changed = zonelist_update(engine->zonelist,
            engine->config->zonelist_filename);
        engine->zonelist->just_removed = 0;
        engine->zonelist->just_added = 0;
        engine->zonelist->just_updated = 0;
        /* [UNLOCK] zonelist */
        lock_basic_unlock(&engine->zonelist->zl_lock);

        /* update zones */
        if (zl_changed == ODS_STATUS_OK) {
            ods_log_debug("[%s] commit zone list changes", engine_str);
            engine_update_zones(engine, &unchanged, &updated, &errors);
            ods_log_debug("[%s] signer configurations: %i updated, "
                "%i errors, %i unchanged", engine_str, updated, errors,
                unchanged);
            updated = 0;
            errors = 0;
            unchanged = 0;
            zl_changed = ODS_STATUS_UNCHANGED;
        }
        engine_run(engine, single_run);
    }

    /* shutdown */
    ods_log_info("[%s] signer shutdown", engine_str);
/*     hsm_close(); */
    engine_stop_cmdhandler(engine);

earlyexit:
    if (engine && engine->config) {
        if (engine->config->pid_filename) {
            (void)unlink(engine->config->pid_filename);
        }
        if (engine->config->clisock_filename) {
            (void)unlink(engine->config->clisock_filename);
        }
    }

    engine_cleanup(engine);
    engine = NULL;
    ods_log_close();
    xmlCleanupParser();
    xmlCleanupGlobals();
    xmlCleanupThreads();
    return;
}


/**
 * Clean up engine.
 *
 */
void
engine_cleanup(engine_type* engine)
{
    allocator_type* allocator;
    cond_basic_type signal_cond;
    lock_basic_type signal_lock;

    if (!engine) {
        return;
    }

    allocator = engine->allocator;
    signal_cond = engine->signal_cond;
    signal_lock = engine->signal_lock;

    zonelist_cleanup(engine->zonelist);
    schedule_cleanup(engine->taskq);

    allocator_deallocate(engine->allocator);
    allocator_cleanup(allocator);

    lock_basic_destroy(&signal_lock);
    lock_basic_off(&signal_cond);

    return;
}
