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
 *
 * Utility tools.
 */

#include "config.h"
#include "util/log.h"
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_rr_get_type() */


/**
 * Check if a RR is a DNSSEC RR (RRSIG, NSEC, NSEC3 or NSEC3PARAMS).
 *
 */
int
util_is_dnssec_rr(ldns_rr* rr)
{
    ldns_rr_type type = 0;
    se_log_assert(rr);

    type = ldns_rr_get_type(rr);
    return (type == LDNS_RR_TYPE_RRSIG ||
            type == LDNS_RR_TYPE_NSEC ||
            type == LDNS_RR_TYPE_NSEC3 ||
            type == LDNS_RR_TYPE_NSEC3PARAMS);
}

/**
 * A more efficient ldns_dnssec_rrs_add_rr(), get rid of ldns_rr_compare().
 *
 */
ldns_status
util_dnssec_rrs_add_rr(ldns_dnssec_rrs *rrs, ldns_rr *rr)
{
    int cmp = 0;
    size_t rr1_len, rr2_len;
    ldns_buffer *rr1_buf;
    ldns_buffer *rr2_buf;
    ldns_dnssec_rrs *new_rrs = NULL;
    ldns_rr* rr1 = NULL;
    ldns_rr* rr2 = NULL;

    if (!rrs || !rr) {
        return LDNS_STATUS_ERR;
    }

    /* name, class and type should already be equal */
    rr1 = rrs->rr;
    rr2 = rr;
    rr1_len = ldns_rr_uncompressed_size(rr1);
    rr2_len = ldns_rr_uncompressed_size(rr2);
    rr1_buf = ldns_buffer_new(rr1_len);
    rr2_buf = ldns_buffer_new(rr2_len);

    if (ldns_rr2buffer_wire_canonical(rr1_buf, rr1, LDNS_SECTION_ANY)
        != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        return LDNS_STATUS_ERR;
    }
    if (ldns_rr2buffer_wire_canonical(rr2_buf, rr2, LDNS_SECTION_ANY)
        != LDNS_STATUS_OK) {
        ldns_buffer_free(rr1_buf);
        ldns_buffer_free(rr2_buf);
        return LDNS_STATUS_ERR;
    }
    cmp = ldns_rr_compare_wire(rr1_buf, rr2_buf);
    ldns_buffer_free(rr1_buf);
    ldns_buffer_free(rr2_buf);

    if (cmp < 0) {
        if (rrs->next) {
            ldns_dnssec_rrs_add_rr(rrs->next, rr);
        } else {
            new_rrs = ldns_dnssec_rrs_new();
            new_rrs->rr = rr;
            rrs->next = new_rrs;
        }
    } else if (cmp > 0) {
        /* put the current old rr in the new next, put the new
           rr in the current container */
        new_rrs = ldns_dnssec_rrs_new();
        new_rrs->rr = rrs->rr;
        new_rrs->next = rrs->next;
        rrs->rr = rr;
        rrs->next = new_rrs;
    } else {
        /* should we error on equal? or free memory of rr */
    }
    return LDNS_STATUS_OK;
}
