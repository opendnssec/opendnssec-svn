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
 * RRset.
 *
 */

#include "config.h"
#include "signer/rrset.h"
#include "util/duration.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_rr_*(), ldns_dnssec_*() */

/**
 * Create new RRset.
 *
 */
rrset_type*
rrset_create(ldns_rr_type rrtype)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));
    se_log_assert(rrtype);
    rrset->rr_type = rrtype;
    rrset->rr_count = 0;
    rrset->inbound_serial = 0;
    rrset->outbound_serial = 0;
    rrset->rrs = ldns_dnssec_rrs_new();
    rrset->rrsigs = NULL;
    return rrset;
}


/** Look if the RR is already present in the RRset */
static int
rrset_covers_rr(ldns_dnssec_rrs* rrs, ldns_rr* rr)
{
    int cmp = 0;
    if (!rrs || !rr) {
        return 0;
    }
    while (rrs) {
        cmp = ldns_rr_compare(rrs->rr, rr);
        if (cmp == 0) {
            return 1;
        }
        rrs = rrs->next;
    }
    return 0;
}


/**
 * Add RR to RRset.
 *
 */
int
rrset_add_rr(rrset_type* rrset, ldns_rr* rr)
{
    rrset_type* walk_rrset = NULL;
    rrset_type* new_rrset = NULL;
    ldns_dnssec_rrs* new_rrs = NULL;

    se_log_assert(rr);
    se_log_assert(rrset);
    se_log_assert(ldns_rr_get_type(rr) == rrset->rr_type);

    if (rrset_covers_rr(rrset->rrs, rr)) {
        /* we have this RR already */
        ldns_rr_free(rr);
    } else {
        /* we can only have one NSEC3PARAMS RR */
        if (rrset->rr_type == LDNS_RR_TYPE_NSEC3PARAMS) {
            if (rrset->rrs) {
                ldns_dnssec_rrs_deep_free(rrset->rrs);
                rrset->rr_count = 0;
            }
            if (rrset->rrsigs) {
                ldns_dnssec_rrs_deep_free(rrset->rrsigs);
            }
        }

        if (!rrset->rrs) {
            rrset->rrs = ldns_dnssec_rrs_new();
            rrset->rrs->rr = rr;
            rrset->rr_count = 1;
        } else {
            status = ldns_dnssec_rrs_add_rr(rrset->rrs, rr);
            if (status != LDNS_STATUS_OK) {
                se_log_error("error adding RR to RRset (%i): %s",
                    rrset->rr_type, ldns_get_errorstr_by_id(status));
                return 1;
            }
            rrset->rr_count += 1;
        }
    }
    return 0;
}


/**
 * Clean up RRset.
 *
 */
void
rrset_cleanup(rrset_type* rrset)
{
    if (rrset) {
        if (rrset->next) {
            rrset_cleanup(rrset->next);
            rrset->next = NULL;
        }
        if (rrset->rrs) {
            ldns_dnssec_rrs_deep_free(rrset->rrs);
            rrset->rrs = NULL;
        }
        if (rrset->rrsigs) {
            ldns_dnssec_rrs_deep_free(rrset->rrsigs);
            rrset->rrsigs = NULL;
        }
        se_free((void*) rrset);
    } else {
        se_log_warning("cleanup empty rrset");
    }
    return;
}
