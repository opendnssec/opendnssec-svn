/*
 * $Id: xfrhandler.c 4518 2011-02-24 15:39:09Z matthijs $
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
 * Zone transfer handler.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "daemon/xfrhandler.h"
#include "shared/duration.h"
#include "shared/status.h"

#include <errno.h>
#include <string.h>

static const char* xfrh_str = "xfrhandler";


/**
 * Create zone transfer handler.
 *
 */
xfrhandler_type*
xfrhandler_create(allocator_type* allocator)
{
    xfrhandler_type* xfrh = NULL;
    if (!allocator) {
        return NULL;
    }
    xfrh = (xfrhandler_type*) allocator_alloc(allocator,
        sizeof(xfrhandler_type));
    if (!xfrh) {
        ods_log_error("[%s] unable to create xfrhandler: "
            "allocator_alloc() failed", xfrh_str);
        return NULL;
    }
    xfrh->allocator = allocator;
    xfrh->engine = NULL;
    xfrh->tcp_set = NULL;
    xfrh->udp_waiting_first = NULL;
    xfrh->udp_waiting_last = NULL;
    xfrh->udp_use_num = 0;
    xfrh->start_time = 0;
    xfrh->current_time = 0;
    xfrh->got_time = 0;
    xfrh->need_to_exit = 0;
    return xfrh;
}


/**
 * Start zone transfer handler.
 *
 */
void
xfrhandler_start(xfrhandler_type* xfrhandler)
{
    engine_type* engine = NULL;
/*
    xfrd_zone_t* zone;
    int i;
*/
    ods_log_assert(xfrhandler);
    ods_log_assert(xfrhandler->engine);
    ods_log_debug("[%s] start", xfrh_str);
    /* setup */
    xfrhandler->start_time = time_now();
    xfrhandler->netio = netio_create(xfrhandler->allocator);
    if (!xfrhandler->netio) {
        ods_fatal_exit("[%s] unable to start xfrhandler: netio_create() "
            "failed", xfrh_str);
    }
    xfrhandler->packet = buffer_create(xfrhandler->allocator,
        PACKET_BUFFER_SIZE);
    if (!xfrhandler->packet) {
        ods_fatal_exit("[%s] unable to start xfrhandler: buffer_create() "
            "failed", xfrh_str);
    }
    xfrhandler->tcp_set = tcp_set_create(xfrhandler->allocator);
    if (!xfrhandler->tcp_set) {
        ods_fatal_exit("[%s] unable to start xfrhandler: tcp_set_create() "
            "failed", xfrh_str);
    }
    engine = (engine_type*) xfrhandler->engine;
    /* service */
    while (xfrhandler->need_to_exit == 0) {
        /* dispatch may block for a longer period, so current is gone */
        xfrhandler->got_time = 0;
        if (netio_dispatch(xfrhandler->netio, NULL, 0) == -1) {
            if (errno != EINTR) {
                ods_log_error("[%s] netio_dispatch failed: %s", xfrh_str,
                    strerror(errno));
            }
        }
    }
    /* shutdown */
    ods_log_debug("[%s] shutdown", xfrh_str);
    return;

/*
    xfrd_write_state(xfrd);
*/
    /* close tcp sockets */
    /* close udp sockets */
}


/**
 * Get current time from zone transfer handler.
 *
 */
time_t
xfrhandler_time(xfrhandler_type* xfrhandler)
{
    if (!xfrhandler) {
        return 0;
    }
    if (!xfrhandler->got_time) {
        xfrhandler->current_time = time_now();
        xfrhandler->got_time = 1;
    }
    return xfrhandler->current_time;
}


/**
 * Signal zone transfer handler.
 *
 */
void
xfrhandler_signal(xfrhandler_type* xfrhandler)
{
    if (xfrhandler) {
        ods_thread_kill(xfrhandler->thread_id, SIGHUP);
    }
    return;
}


/**
 * Cleanup zone transfer handler.
 *
 */
void
xfrhandler_cleanup(xfrhandler_type* xfrhandler)
{
    allocator_type* allocator = NULL;
    if (!xfrhandler) {
        return;
    }
    allocator = xfrhandler->allocator;
    netio_cleanup(xfrhandler->netio);
    allocator_deallocate(allocator, (void*) xfrhandler);
    return;
}
