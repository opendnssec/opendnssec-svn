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
 * Domain.
 *
 */

#include "config.h"
#include "signer/domain.h"
#include "signer/rrset.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h>


/**
 * Create empty domain.
 *
 */
domain_type*
domain_create(ldns_rdf* dname)
{
    domain_type* domain = (domain_type*) se_malloc(sizeof(domain_type));
    se_log_assert(dname);

    domain->name = ldns_rdf_clone(dname);
    domain->parent = NULL;
    domain->nsec3 = NULL;
    domain->auth_rrset = NULL;
    domain->ns_rrset = NULL;
    domain->ds_rrset = NULL;
    domain->nsec_rrset = NULL;
    domain->domain_status = DOMAIN_STATUS_NONE;
    domain->inbound_serial = 0;
    return domain;
}


/**
 * Add RR to domain.
 *
 */
int
domain_add_rr(domain_type* domain, ldns_rr* rr)
{
    ldns_rr_type rr_type = 0, type_covered = 0;

    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(rr);
    se_log_assert((ldns_dname_compare(ldns_rr_owner(rr), ldns_rr_owner(rr)) == 0));

    rr_type = ldns_rr_get_type(rr);
    /* denial of existence, skip: done with domain_nsecify */
    if (rr_type == LDNS_RR_TYPE_NSEC || rr_type == LDNS_RR_TYPE_NSEC3) {
        return 0;
    }

    /* delegation */
    if (rr_type == LDNS_RR_TYPE_NS &&
        domain->domain_status != DOMAIN_STATUS_APEX) {
        if (!domain->ns_rrset) {
            domain->ns_rrset = rrset_create(rr);
            return 0;
        }
        return rrset_add_rr(domain->ns_rrset, rr);
    }

    /* delegation signer */
    if (rr_type == LDNS_RR_TYPE_DS) {
        if (!domain->ds_rrset) {
            domain->ds_rrset = rrset_create(rr);
            return 0;
        }
        return rrset_add_rr(domain->ds_rrset, rr);
    }

    /* signature */
    if (rr_type == LDNS_RR_TYPE_RRSIG) {
        type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
        if (type_covered == LDNS_RR_TYPE_NSEC ||
            type_covered == LDNS_RR_TYPE_NSEC3) {
            se_log_assert(domain->nsec_rrset);
            return rrset_add_rr(domain->nsec_rrset, rr);
        } else if (type_covered == LDNS_RR_TYPE_DS) {
            se_log_assert(domain->ds_rrset);
            return rrset_add_rr(domain->ds_rrset, rr);
        } else {
            se_log_assert(domain->auth_rrset);
            return rrset_add_rr(domain->auth_rrset, rr);
        }
    }

    /* authoritative */
    if (!domain->auth_rrset) {
        domain->auth_rrset = rrset_create(rr);
        return 0;
    }
    return rrset_add_rr(domain->auth_rrset, rr);
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (domain) {
        if (domain->name) {
            ldns_rdf_deep_free(domain->name);
            domain->name = NULL;
        }
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    } else {
        se_log_warning("cleanup empty domain");
    }
}
