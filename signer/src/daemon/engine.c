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
 * The engine.
 *
 */

#include "config.h"
#include "daemon/cmdhandler.h"
#include "daemon/config.h"
#include "daemon/engine.h"
#include "daemon/signal.h"
#include "scheduler/locks.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <libhsm.h> /* hsm_open(), hsm_close() */
#include <libxml/parser.h> /* xmlInitParser(), xmlCleanupParser(), xmlCleanupThreads() */
#include <signal.h> /* sigfillset(), sigaction() */
#include <stdio.h> /* snprintf() */
#include <stdlib.h> /* exit(), fwrite() */
#include <string.h> /* strlen() */
#include <sys/types.h> /* getpid() */
#include <time.h> /* tzset() */
#include <unistd.h> /* fork(), setsid(), getpid() */


/**
 * Create engine.
 *
 */
engine_type*
engine_create(void)
{
    engine_type* engine = (engine_type*) se_malloc(sizeof(engine_type));

    se_log_debug("create signer engine");
    engine->config = NULL;
    engine->daemonize = 0;
    engine->cmdhandler = NULL;
    engine->cmdhandler_done = 0;
    engine->pid = -1;
    engine->need_to_exit = 0;
    engine->need_to_reload = 0;
    engine->signal = SIGNAL_INIT;
    lock_basic_init(&engine->signal_lock);
    lock_basic_set(&engine->signal_cond);
    return engine;
}


/**
 * Start command handler thread.
 *
 */
static void*
cmdhandler_thread_start(void* arg)
{
    cmdhandler_type* cmd = (cmdhandler_type*) arg;

    se_thread_blocksigs();
    cmdhandler_start(cmd);
    return NULL;
}


/**
 * Start command handler.
 *
 */
static int
engine_start_cmdhandler(engine_type* engine)
{
    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("start command handler");

    engine->cmdhandler = cmdhandler_create(engine->config->clisock_filename);
    if (!engine->cmdhandler) {
        return 1;
    }
    engine->cmdhandler->engine = engine;

    se_thread_create(&engine->cmdhandler->thread_id,
        cmdhandler_thread_start, engine->cmdhandler);

    return 0;
}


/**
 * Stop parent process.
 *
 */
static void
parent_cleanup(engine_type* engine)
{
    if (engine) {
        engine_config_cleanup(engine->config);
        se_free((void*) engine);
    } else {
        se_log_warning("cleanup empty parent");
    }
}


/**
 * Write process id to file.
 *
 */
static int
write_pidfile(const char* pidfile, pid_t pid)
{
    FILE* fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    se_log_assert(pidfile);
    se_log_assert(pid);
    se_log_debug("writing pid %lu to pidfile %s", (unsigned long) pid,
        pidfile);
    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    fd = se_fopen(pidfile, NULL, "w");
    if (!fd) {
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0) {
        result = 1;
    } else {
        result = fwrite((const void*) pidbuf, 1, size, fd);
    }
    if (result == 0) {
        se_log_error("write to pidfile %s failed: %s", pidfile,
            strerror(errno));
    } else if (result < size) {
        se_log_error("short write to pidfile %s: disk full?", pidfile);
        result = 0;
    } else {
        result = 1;
    }
    se_fclose(fd);
    if (!result) {
        return -1;
    }
    return 0;
}


/**
 * Set up engine.
 *
 */
static int
engine_setup(engine_type* engine)
{
    struct sigaction action;
    int result = 0;

    se_log_assert(engine);
    se_log_assert(engine->config);
    se_log_debug("perform setup");

    /* start command handler (before chowning socket file) */
    if (engine_start_cmdhandler(engine) != 0) {
        se_log_error("setup failed: unable to start command handler");
        return 1;
    }

    /* privdrop */

    /* daemonize */
    if (engine->daemonize) {
        switch ((engine->pid = fork())) {
            case -1: /* error */
                se_log_error("setup failed: unable to fork daemon: %s",
                    strerror(errno));
                return 1;
            case 0: /* child */
                break;
            default: /* parent */
                parent_cleanup(engine);
                xmlCleanupParser();
                xmlCleanupThreads();
                exit(0);
        }
        if (setsid() == -1) {
            se_log_error("setup failed: unable to setsid daemon (%s)",
                strerror(errno));
            return 1;
        }
    }
    engine->pid = getpid();
    if (write_pidfile(engine->config->pid_filename, engine->pid) == -1) {
        se_log_error("setup failed: unable to write pid file");
        return 1;
    }
    se_log_verbose("running as pid %lu", (unsigned long) engine->pid);

    /* catch signals */
    signal_set_engine(engine);
    action.sa_handler = signal_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    /* set up hsm */
    result = hsm_open(engine->config->cfg_filename, hsm_prompt_pin, NULL);
    if (result != HSM_OK) {
        se_log_error("Error initializing libhsm");
        return 1;
    }

    /* set up the work floor */

    return 0;
}


/**
 * Engine running.
 *
 */
static void
engine_run(engine_type* engine)
{
    se_log_assert(engine);

    engine->signal = SIGNAL_RUN;
    while (engine->need_to_exit == 0 && engine->need_to_reload == 0) {
        lock_basic_lock(&engine->signal_lock);
        engine->signal = signal_capture(engine->signal);
        switch (engine->signal) {
            case SIGNAL_RUN:
                se_log_assert(1);
                break;
            case SIGNAL_RELOAD:
                engine->need_to_reload = 1;
                break;
            case SIGNAL_SHUTDOWN:
                engine->need_to_exit = 1;
                break;
            default:
                se_log_warning("invalid signal captured: %d, keep running",
                    engine->signal);
                engine->signal = SIGNAL_RUN;
                break;
        }

        if (engine->signal == SIGNAL_RUN) {
           se_log_debug("engine taking a break");
           lock_basic_sleep(&engine->signal_cond, &engine->signal_lock, 3600);
        }
        lock_basic_unlock(&engine->signal_lock);
    }
    se_log_debug("engine halt");
    return;
}


/**
 * Start engine.
 *
 */
void
engine_start(const char* cfgfile, int cmdline_verbosity, int daemonize,
    int info)
{
    engine_type* engine = NULL;
    int use_syslog = 0;

    se_log_assert(cfgfile);
    se_log_init(NULL, use_syslog, cmdline_verbosity);
    se_log_verbose("start signer engine");

    /* initialize */
    xmlInitParser();
    engine = engine_create();
    engine->daemonize = daemonize;

    /* configure */
    engine->config = engine_config(cfgfile, cmdline_verbosity);
    if (engine_check_config(engine->config) != 0) {
        se_log_error("cfgfile %s has errors", cfgfile);
        engine->need_to_exit = 1;
    }
    if (info) {
        engine_config_print(stdout, engine->config);
        xmlCleanupParser();
        xmlCleanupThreads();
        engine_cleanup(engine);
        engine = NULL;
        return;
    }

    /* open log */
    se_log_init(engine->config->log_filename, engine->config->use_syslog,
       engine->config->verbosity);

    /* setup */
    tzset(); /* for portability */
    if (engine_setup(engine) != 0) {
        se_log_error("signer engine setup failed");
        engine->need_to_exit = 1;
    }

    /* run */
    while (engine->need_to_exit == 0) {
        if (engine->need_to_reload) {
            se_log_verbose("reload engine");
            engine->need_to_reload = 0;
        } else {
            se_log_debug("signer engine started");
        }

        engine_run(engine);
    }

    /* shutdown */
    se_log_verbose("shutdown signer engine");
    hsm_close();
    (void)unlink(engine->config->pid_filename);
    (void)unlink(engine->config->clisock_filename);
    engine_cleanup(engine);
    engine = NULL;
    se_log_close();
    xmlCleanupParser();
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
    if (engine) {
        if (engine->cmdhandler) {
            cmdhandler_cleanup(engine->cmdhandler);
            engine->cmdhandler = NULL;
        }
        if (engine->config) {
            engine_config_cleanup(engine->config);
            engine->config = NULL;
        }
        lock_basic_destroy(&engine->signal_lock);
        lock_basic_off(&engine->signal_cond);
        se_free((void*) engine);
    } else {
        se_log_warning("cleanup empty engine");
    }
    return;
}
