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
#include "signer/hsm.h"
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
rrset_create(ldns_rr* rr)
{
    rrset_type* rrset = (rrset_type*) se_calloc(1, sizeof(rrset_type));
    se_log_assert(rr);
    rrset->rr_type = ldns_rr_get_type(rr);
    rrset->rrs = ldns_dnssec_rrs_new();
    rrset->rrs->rr = rr;
    rrset->rrsigs = NULL;
    return rrset;
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
 * Look if the RR is already present in the RRset.
 *
 */
int
rrset_covers_rrtype(rrset_type* rrset, ldns_rr_type rr_type)
{
    while (rrset) {
        if (rrset->rr_type == rr_type &&
            rrset->rrs && rrset->rrs->rr) {
            return 1;
        }
        rrset = rrset->next;
    }
    return 0;
}


/**
 * Print RRset.
 *
 */
void
rrset_print(FILE* fd, rrset_type* rrset, const char* comments, int follow,
    int glue_only, int skip_soa)
{
    rrset_type* walk_rrset = rrset;

    while (walk_rrset) {
        if (!walk_rrset->rrs || !walk_rrset->rrs->rr) {
            walk_rrset = walk_rrset->next;
            continue;
        }
        if (comments) {
            fprintf(fd, "; %s\n", comments);
            comments = NULL;
        }
        if (walk_rrset->rr_type == LDNS_RR_TYPE_SOA && skip_soa) {
            walk_rrset = walk_rrset->next;
            continue;
        }
        if ((walk_rrset->rr_type != LDNS_RR_TYPE_A &&
             walk_rrset->rr_type != LDNS_RR_TYPE_AAAA) && glue_only) {
            walk_rrset = walk_rrset->next;
            continue;
        }
        ldns_dnssec_rrs_print(fd, walk_rrset->rrs);
        if (walk_rrset->rrsigs) {
            ldns_dnssec_rrs_print(fd, walk_rrset->rrsigs);
        }
        if (!follow) {
            break;
        }
        walk_rrset = walk_rrset->next;
    }
    return;
}
