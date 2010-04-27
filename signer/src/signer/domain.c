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
 * Compare RRsets.
 *
 */
static int
rrset_compare(const void* a, const void* b)
{
    rrset_type* x = (rrset_type*)a;
    rrset_type* y = (rrset_type*)b;
    return x->rr_type - y->rr_type;
}


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
    domain->rrset = ldns_rbtree_create(rrset_compare);
    domain->domain_status = DOMAIN_STATUS_NONE;
    domain->inbound_serial = 0;
    domain->outbound_serial = 0;
    return domain;
}


/**
 * Convert RRset to a tree node.
 *
 */
static ldns_rbnode_t*
rrset2node(rrset_type* rrset)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    node->key = rrset->rr_type;
    node->data = rrset;
    return node;
}


/**
 * Lookup RRset within domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    se_log_assert(rrset);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    node = ldns_rbtree_search(domain->rrsets, rrset->rr_type);
    if (node && node != LDNS_RBTREE_NULL) {
        return (rrset_type*) node->data;
    }
    return NULL;
}


/**
 * Add RRset to domain.
 *
 */
rrset_type*
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    char* str = NULL;

    se_log_assert(rrset);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    new_node = rrset2node(rrset);
    if (ldns_rbtree_insert(domain->rrsets, new_node) == NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add RRset %i to domain %s",
            rrset->rr_type, domain->name);
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    return rrset;
}


/**
 * Perform add updates at the domain
 *
 */
static int
domain_commit_add_rr(domain_type* domain, ldns_rr* rr)
{
    ldns_rr_type rrtype = 0;
    rrset_type* rrset = NULL;
    rrset_type* rrset2 = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    rrtype = ldns_rr_get_type(poprr));
    rrset = rrset_create(rrtype);
    rrset2 = domain_lookup_rrset(domain, rrset);
    if (rrset2) {
        rrset_cleanup(rrset);
        rrset2->inbound_serial = domain->inbound_serial;
    } else {
        rrset2 = domain_add_rrset(domain, rrset);
        if (!rrset2) {
            se_log_error("unable to add RR to domain: failed to add RRset");
            rrset_cleanup(rrset);
            return 1;
        }
        rrset2->inbound_serial = domain->inbound_serial;
    }
   se_log_assert(rrset2);
   return rrset_add_rr(rrset2, rr);
}


/**
 * Commit the added and deleted RRs.
 *
 */
int
domain_commit_changes(domain_type* domain, uint32_t serial)
{
    size_t old_rrset_count = 0;
    size_t new_rrset_count = 0;
    ldns_rr* poprr = NULL;

    se_log_assert(serial);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (domain->inbound_serial < serial) {
        /* domain obsoleted */
    }

    /* current no. of RRsets */
    old_rrset_count = domain->rrsets->count;

    /* del RRs */
    if (ldns_rr_list_rr_count(domain->rrs_del) > 0) {
        while ( (poprr = ldns_rr_list_pop_rr(domains->rrs_del)) != NULL) {
            se_log_warning("delete RRs not implemented yet");
        }
    }

    /* add RRs */
    if (ldns_rr_list_rr_count(domain->rrs_add) > 0) {
        while ( (poprr = ldns_rr_list_pop_rr(domains->rrs_add)) != NULL) {
            if (domain_commit_add_rr(domain, poprr) != 0) {
                se_log_error("unable to commit changes: failed to add RR to "
                    "domain");
                return 1;
            }
        }
    }

    /* new no. of RRsets */
    new_rrset_count = domain->rrsets->count;

    if (new_rrset_count <= 0) {
        /* domain obsoleted */
    } else if (old_rrset_count > 0) {
        /* domain updated */
    } else {
        /* domain added */
    }
    return 0;
}


/**
 * Add RR to the list of pending changes.
 *
 */
static int
domain_pend_rr(domain_type* domain, ldns_rr* rr, uint32_t serial, int del)
{
    ldns_rr_type rr_type = 0;
    ldns_status status = LDNS_STATUS_OK;

    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    /* TODO: util/tools.h is_dnssec_rr() */
    rr_type = ldns_rr_get_type(rr);
    if (rr_type == LDNS_RR_TYPE_NSEC ||
        rr_type == LDNS_RR_TYPE_NSEC3 ||
        rr_type == LDNS_RR_TYPE_NSEC3PARAMS ||
        rr_type == LDNS_RR_TYPE_RRSIG) {
        return LDNS_STATUS_OK;
    }

    if (del) {
        status = ldns_rr_list_push_rr(domain->rrs_del, rr);
    } else {
        status = ldns_rr_list_push_rr(domain->rrs_add, rr);
    }
    if (status == LDNS_STATUS_OK) {
        domain->inbound_serial = serial;
    }
    return status;
}


/**
 * Add RR to the list of RRs to add to this domain.
 *
 */
int
domain_add_rr(domain_type* domain, ldns_rr* rr, uint32_t serial)
{
    se_log_assert(domain->rrs_add);
    if (domain_pend_rr(domain, rr, serial, 0) == LDNS_STATUS_OK) {
        return 0;
    }
    return 1;
}


/**
 * Add RR to the list of RRs to delete from to this domain.
 *
 */
int
domain_del_rr(domain_type* domain, ldns_rr* rr, uint32_t serial)
{
    se_log_assert(domain->rrs_del);
    if (domain_pend_rr(domain, rr, serial, 1) == LDNS_STATUS_OK) {
        return 0;
    }
    return 1;
}


/**
 * Clean up RRsets at the domain.
 *
 */
static void
domain_cleanup_rrsets(ldns_rbtree_t* rrset_tree)
{
    ldns_rbnode_t* node = NULL;
    rrset_type* rrset = NULL;

    if (rrset_tree && rrset_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(rrset_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_cleanup(rrset);
        node = ldns_rbtree_next(node);
    }
    se_rbnode_free(rrset_tree->root);
    ldns_rbtree_free(rrset_tree);
    return;
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
        if (domain->rrsets) {
            domain_cleanup_rrsets(domain->rrsets);
            domain->rrsets = NULL;
        }
        if (domain->rrs_add) {
            ldns_rr_list_deep_free(domain->rrs_add);
            domain->rrs_add = NULL;
        }
        if (domain->rrs_del) {
            ldns_rr_list_deep_free(domain->rrs_del);
            domain->rrs_del = NULL;
        }
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    } else {
        se_log_warning("cleanup empty domain");
    }
    return;
}



