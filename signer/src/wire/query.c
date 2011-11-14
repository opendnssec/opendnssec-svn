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
#include "daemon/engine.h"
#include "wire/query.h"

const char* query_str = "query";


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
    q->buffer = buffer_create(allocator, PACKET_BUFFER_SIZE);
    if (!q->buffer) {
        query_cleanup(q);
        return NULL;
    }
    query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
    return q;
}


/**
 * Reset query.
 *
 */
void
query_reset(query_type* q, size_t maxlen, int is_tcp)
{
    if (!q) {
        return;
    }
    q->addrlen = sizeof(q->addr);
    q->maxlen = maxlen;
    q->reserved_space = 0;
    buffer_clear(q->buffer);
    /* edns */
    /* tsig */
    q->tcp = is_tcp;
    q->tcplen = 0;
    /* qname, qtype, qclass */
    q->zone = NULL;
    /* domain, opcode, cname count, delegation, compression, temp */
    q->axfr_is_done = 0;
    q->axfr_fd = NULL;
    return;
}


/**
 * Process query.
 *
 */
query_state
query_process(query_type* q, void* engine)
{
    engine_type* e = (engine_type*) engine;
    ods_log_assert(e);
    ods_log_assert(q);
    ods_log_assert(q->buffer);
    if (!e || !q || !q->buffer) {
        ods_log_error("[%s] drop query: assertion error", query_str);
        return QUERY_DISCARDED; /* should not happen */
    }
    if (buffer_limit(q->buffer) < BUFFER_PKT_HEADER_SIZE) {
        ods_log_error("[%s] drop query: packet too small", query_str);
        return QUERY_DISCARDED; /* too small */
    }
    if (buffer_pkt_qr(q->buffer)) {
        ods_log_error("[%s] drop query: qr bit set", query_str);
        return QUERY_DISCARDED; /* not a query */
    }
    /* parse packet */

/*
    ldns_status status = LDNS_STATUS_OK;
    status = ldns_wire2pkt(pkt, inbuf, (size_t)inlen);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] got bad packet: %s", sock_str,
            ldns_get_errorstr_by_id(status));
        return ODS_STATUS_ERR;
    }
    *rr = ldns_rr_list_rr(ldns_pkt_question(*pkt), 0);
    ods_log_assert(e);
    lock_basic_lock(&e->zonelist->zl_lock);
    *zone = zonelist_lookup_zone_by_dname(e->zonelist, ldns_rr_owner(*rr),
        ldns_rr_get_class(*rr));
    if (*zone && (*zone)->zl_status == ZONE_ZL_ADDED) {
        *zone = NULL;
    }
    lock_basic_unlock(&e->zonelist->zl_lock);
    return ODS_STATUS_OK;
*/

    buffer_pkt_set_qr(q->buffer);
    return QUERY_PROCESSED;
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
    buffer_cleanup(q->buffer, allocator);
    allocator_deallocate(allocator, (void*)q);
    allocator_cleanup(allocator);
    return;
}
