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
 * Error.
 *
 */
static query_state
query_error(query_type* q, ldns_pkt_rcode rcode)
{
    size_t limit = 0;
    if (!q) {
        return QUERY_DISCARDED;
    }
    limit = buffer_limit(q->buffer);
    buffer_clear(q->buffer);
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_rcode(q->buffer, rcode);
    buffer_pkt_set_ancount(q->buffer, 0);
    buffer_pkt_set_nscount(q->buffer, 0);
    buffer_pkt_set_arcount(q->buffer, 0);
    buffer_set_position(q->buffer, limit);
    return QUERY_PROCESSED;
}


/**
 * FORMERR.
 *
 */
static query_state
query_formerr(query_type* q)
{
    ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
    if (!q) {
        return QUERY_DISCARDED;
    }
    opcode = buffer_pkt_opcode(q->buffer);
    /* preserve the RD flag, clear the rest */
    buffer_pkt_set_flags(q->buffer, buffer_pkt_flags(q->buffer) & 0x0100U);
    buffer_pkt_set_opcode(q->buffer, opcode);
    buffer_pkt_set_qdcount(q->buffer, 0);
    ods_log_debug("[%s] formerr", query_str);
    return query_error(q, LDNS_RCODE_FORMERR);
}


/**
 * SERVFAIL.
 *
 */
static query_state
query_servfail(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] servfail", query_str);
    buffer_set_position(q->buffer, 0);
    buffer_set_limit(q->buffer, BUFFER_PKT_HEADER_SIZE);
    buffer_pkt_set_qdcount(q->buffer, 0);
    return query_error(q, LDNS_RCODE_SERVFAIL);
}


/**
 * NOTIMPL.
 *
 */
static query_state
query_notimpl(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] notimpl", query_str);
    return query_error(q, LDNS_RCODE_NOTIMPL);
}


/**
 * REFUSED.
 *
 */
static query_state
query_refused(query_type* q)
{
    if (!q) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] refused", query_str);
    return query_error(q, LDNS_RCODE_REFUSED);
}


/**
 * NOTIFY.
 *
 */
static query_state
query_process_notify(query_type* q, ldns_rr_type qtype)
{
    dnsin_type* dnsin = NULL;
    size_t limit = 0;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(q->zone->name);
    ods_log_debug("[%s] incoming notify for zone %s", query_str,
        q->zone->name);
    if (buffer_pkt_rcode(q->buffer) != LDNS_RCODE_NOERROR ||
        buffer_pkt_qr(q->buffer) ||
        !buffer_pkt_aa(q->buffer) ||
        buffer_pkt_tc(q->buffer) ||
        buffer_pkt_rd(q->buffer) ||
        buffer_pkt_ra(q->buffer) ||
        buffer_pkt_ad(q->buffer) ||
        buffer_pkt_cd(q->buffer) ||
        buffer_pkt_qdcount(q->buffer) != 1 ||
        buffer_pkt_ancount(q->buffer) > 1 ||
        buffer_pkt_nscount(q->buffer) != 0 ||
        buffer_pkt_arcount(q->buffer) != 0 ||
        qtype != LDNS_RR_TYPE_SOA) {
        return query_formerr(q);
    }
    if (!q->zone->adinbound || q->zone->adinbound->type != ADAPTER_DNS) {
        ods_log_error("[%s] zone %s is not configured to have input dns "
            "adapter", query_str, q->zone->name);
        return query_refused(q);
    }
    ods_log_assert(q->zone->adinbound->config);
    dnsin = (dnsin_type*) q->zone->adinbound->config;
    if (!acl_find(dnsin->allow_notify, &q->addr, NULL)) {
        return query_refused(q);
    }
    limit = buffer_limit(q->buffer);
    /* get answer section and check inbound serial */
    /* forward notify to xfrd */
    buffer_pkt_set_qr(q->buffer);
    buffer_pkt_set_aa(q->buffer);
    buffer_pkt_set_ancount(q->buffer, 0);
    buffer_clear(q->buffer);
    buffer_set_position(q->buffer, limit);
    return QUERY_PROCESSED;
}


/**
 * Add RRset to response.
 *
 */
static int
response_add_rrset(response_type* r, rrset_type* rrset,
    ldns_pkt_section section)
{
    if (!r || !rrset || !section) {
        return 0;
    }
    /* duplicates? */
    r->sections[r->rrset_count] = section;
    r->rrsets[r->rrset_count] = rrset;
    ++r->rrset_count;
    return 1;
}


/**
 * Encode RR.
 *
 */
static int
response_encode_rr(query_type* q, ldns_rr* rr, ldns_pkt_section section)
{
    uint8_t *data = NULL;
    size_t size = 0;
    ldns_status status = LDNS_STATUS_OK;
    ods_log_assert(q);
    ods_log_assert(rr);
    ods_log_assert(section);
    status = ldns_rr2wire(&data, rr, section, &size);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to send good response: ldns_rr2wire() "
            "failed (%s)", query_str, ldns_get_errorstr_by_id(status));
        return 0;
    }
    buffer_write(q->buffer, (const void*) data, size);
    LDNS_FREE(data);
    return 1;
}


/**
 * Encode RRset.
 *
 */
static uint16_t
response_encode_rrset(query_type* q, rrset_type* rrset,
    ldns_pkt_section section)
{
    uint16_t i = 0;
    uint16_t added = 0;
    ods_log_assert(q);
    ods_log_assert(rrset);
    ods_log_assert(section);

    for (i = 0; i < rrset->rr_count; i++) {
        added += response_encode_rr(q, rrset->rrs[i].rr, section);
    }
    for (i = 0; i < rrset->rrsig_count; i++) {
        added += response_encode_rr(q, rrset->rrsigs[i].rr, section);
    }
    /* truncation? */
    return added;
}


/**
 * Encode response.
 *
 */
static void
response_encode(query_type* q, response_type* r)
{
    uint16_t counts[LDNS_SECTION_ANY];
    ldns_pkt_section s = LDNS_SECTION_QUESTION;
    size_t i = 0;
    ods_log_assert(q);
    ods_log_assert(r);
    for (s = LDNS_SECTION_ANSWER; s < LDNS_SECTION_ANY; s++) {
        counts[s] = 0;
    }
    for (s = LDNS_SECTION_ANSWER; s < LDNS_SECTION_ANY; s++) {
        for (i = 0; i < r->rrset_count; i++) {
            if (r->sections[i] == s) {
                counts[s] += response_encode_rrset(q, r->rrsets[i], s);
            }
        }
    }
    buffer_pkt_set_ancount(q->buffer, counts[LDNS_SECTION_ANSWER]);
    buffer_pkt_set_nscount(q->buffer, counts[LDNS_SECTION_AUTHORITY]);
    buffer_pkt_set_arcount(q->buffer, counts[LDNS_SECTION_ADDITIONAL]);
    return;
}


/**
 * Query response.
 *
 */
static query_state
query_response(query_type* q, ldns_rr_type qtype)
{
    rrset_type* rrset = NULL;
    response_type r;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    r.rrset_count = 0;
    lock_basic_lock(&q->zone->zone_lock);
    rrset = zone_lookup_rrset(q->zone, q->zone->apex, qtype);
    if (rrset) {
        if (!response_add_rrset(&r, rrset, LDNS_SECTION_ANSWER)) {
            lock_basic_unlock(&q->zone->zone_lock);
            return query_servfail(q);
        }
        /* NS RRset goes into Authority Section */
        rrset = zone_lookup_rrset(q->zone, q->zone->apex, LDNS_RR_TYPE_NS);
        if (rrset) {
            if (!response_add_rrset(&r, rrset, LDNS_SECTION_AUTHORITY)) {
                lock_basic_unlock(&q->zone->zone_lock);
                return query_servfail(q);
            }
        }
    } else if (qtype != LDNS_RR_TYPE_SOA) {
        rrset = zone_lookup_rrset(q->zone, q->zone->apex, LDNS_RR_TYPE_SOA);
        if (rrset) {
            if (!response_add_rrset(&r, rrset, LDNS_SECTION_AUTHORITY)) {
                lock_basic_unlock(&q->zone->zone_lock);
                return query_servfail(q);
            }
        }
    } else {
        lock_basic_unlock(&q->zone->zone_lock);
        return query_servfail(q);
    }
    lock_basic_unlock(&q->zone->zone_lock);

    response_encode(q, &r);
    /* compression */
    return QUERY_PROCESSED;
}


/**
 * QUERY.
 *
 */
static query_state
query_process_query(query_type* q, ldns_rr_type qtype)
{
    dnsout_type* dnsout = NULL;
    uint16_t limit = 0;
    uint16_t flags = 0;
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_assert(q->zone->name);
    ods_log_debug("[%s] incoming query for zone %s", query_str,
        q->zone->name);
    /* sanity checks */
    if (buffer_pkt_qdcount(q->buffer) != 1 || buffer_pkt_tc(q->buffer)) {
        buffer_pkt_set_flags(q->buffer, 0);
        return query_formerr(q);
    }
    /* acl */
    if (!q->zone->adoutbound || q->zone->adoutbound->type != ADAPTER_DNS) {
        ods_log_error("[%s] zone %s is not configured to have output dns "
            "adapter", query_str, q->zone->name);
        return query_refused(q);
    }
    ods_log_assert(q->zone->adoutbound->config);
    dnsout = (dnsout_type*) q->zone->adoutbound->config;
    if (!acl_find(dnsout->provide_xfr, &q->addr, NULL)) {
        return query_refused(q);
    }
    /* zone transfer? */
    if (qtype == LDNS_RR_TYPE_AXFR || qtype == LDNS_RR_TYPE_IXFR) {
        ods_log_assert(q->zone->name);
        ods_log_debug("[%s] incoming transfer request for zone %s",
            query_str, q->zone->name);
        return query_notimpl(q);
    }
    /* prepare */
    limit = buffer_limit(q->buffer);
    flags = buffer_pkt_flags(q->buffer);
    flags &= 0x0100U; /* preserve the rd flag */
    flags |= 0x8000U; /* set the qr flag */
    buffer_pkt_set_flags(q->buffer, flags);
    buffer_clear(q->buffer);
    buffer_set_position(q->buffer, limit);
    /* (soa) query */
    return query_response(q, qtype);
}


/**
 * UPDATE.
 *
 */
static query_state
query_process_update(query_type* q)
{
    if (!q || !q->zone) {
        return QUERY_DISCARDED;
    }
    ods_log_debug("[%s] dynamic update not implemented", query_str);
    return query_notimpl(q);
}


/**
 * Process query.
 *
 */
query_state
query_process(query_type* q, void* engine)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt* pkt = NULL;
    ldns_rr* rr = NULL;
    ldns_pkt_opcode opcode = LDNS_PACKET_QUERY;
    ldns_rr_type qtype = LDNS_RR_TYPE_SOA;
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
    status = ldns_wire2pkt(&pkt, buffer_current(q->buffer),
        buffer_remaining(q->buffer));
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] got bad packet: %s", query_str,
            ldns_get_errorstr_by_id(status));
        return query_formerr(q);
    }
    rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
    lock_basic_lock(&e->zonelist->zl_lock);
    /* we can just lookup the zone, because we will only handle SOA queries,
       zone transfers, updates and notifies */
    q->zone = zonelist_lookup_zone_by_dname(e->zonelist, ldns_rr_owner(rr),
        ldns_rr_get_class(rr));
    /* don't answer for zones that are just added */
    if (q->zone && q->zone->zl_status == ZONE_ZL_ADDED) {
        q->zone = NULL;
    }
    lock_basic_unlock(&e->zonelist->zl_lock);
    opcode = ldns_pkt_get_opcode(pkt);
    qtype = ldns_rr_get_type(rr);
    ldns_pkt_free(pkt);
    if (!q->zone) {
        return query_servfail(q);
    }
    switch(opcode) {
        case LDNS_PACKET_NOTIFY:
            return query_process_notify(q, qtype);
        case LDNS_PACKET_QUERY:
            return query_process_query(q, qtype);
        case LDNS_PACKET_UPDATE:
            return query_process_update(q);
        default:
            return query_notimpl(q);
    }
    return query_notimpl(q);
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
