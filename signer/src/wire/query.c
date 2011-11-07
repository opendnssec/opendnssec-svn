/*
 * $Id: query.c 4958 2011-04-18 07:11:09Z matthijs $
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
 * Query.
 *
 */

#include "config.h"
#include "wire/query.h"


/**
 * Create query.
 *
 */
query_type*
query_create(void)
{
    allocator_type* allocator = NULL;
    query_type* q = NULL;
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        return NULL;
    }
    q = (query_type*) allocator_alloc(allocator, sizeof(query_type));
    if (!q) {
        allocator_cleanup(allocator);
        return NULL;
    }
    q->allocator = allocator;
    query_reset(q, UDP_MAX_MESSAGE_LEN);
    return q;
}


/**
 * Reset query.
 *
 */
void
query_reset(query_type* q, size_t maxlen)
{
    if (!q) {
        return;
    }
    q->maxlen = maxlen;
    /* tsig */
    q->tcp = 0;
    q->tcplen = 0;
    q->zone = NULL;
    q->axfr_is_done = 0;
    q->fd = -1;
    return;
}


/**
 * Cleanup query.
 *
 */
void
query_cleanup(query_type* q)
{
    allocator_type* allocator = NULL;
    if (!q) {
        return;
    }
    allocator = q->allocator;
    allocator_deallocate(allocator, (void*)q);
    allocator_cleanup(allocator);
    return;
}
