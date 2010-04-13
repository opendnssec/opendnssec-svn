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
#include "scheduler/locks.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <libxml/parser.h> /* xmlInitParser(), xmlCleanupParser(), xmlCleanupThreads() */
#include <time.h> /* tzset */

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

    engine->need_to_exit = 0;
    engine->need_to_reload = 0;

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
 * Set up engine.
 *
 */
static int
engine_setup(engine_type* engine)
{
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

    /* catch signals */

    /* set up hsm */

    /* set up the work floor */

    return 0;
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
    int use_syslog = 1;

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
        return;
    }
    if (info) {
        engine_config_print(stdout, engine->config);
        xmlCleanupParser();
        xmlCleanupThreads();
        engine_cleanup(engine);
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
        engine->need_to_exit = 1;
    }
    /* shutdown */

    se_log_verbose("shutdown signer engine");

    engine_cleanup(engine);
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
        if (engine->config) {
            engine_config_cleanup(engine->config);
        }
        se_free((void*) engine);
    } else {
        se_log_warning("cleanup empty engine");
    }
    return;
}
