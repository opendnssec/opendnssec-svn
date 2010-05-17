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
#include "util/util.h"

#include <ldns/ldns.h> /* ldns_*() */


/**
 * Compare RRsets.
 *
 */
static int
rrset_compare(const void* a, const void* b)
{
    ldns_rr_type* x = (ldns_rr_type*)a;
    ldns_rr_type* y = (ldns_rr_type*)b;
    return (*x)-(*y);
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
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    domain->domain_status = DOMAIN_STATUS_NONE;
    domain->inbound_serial = 0;
    domain->outbound_serial = 0;
    /* nsec */
    domain->nsec_serial = 0;
    domain->nsec_bitmap_changed = 0;
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
    node->key = &(rrset->rr_type);
    node->data = rrset;
    return node;
}


/**
 * Lookup RRset within domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type type)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    node = ldns_rbtree_search(domain->rrsets, &(type));
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
        se_log_error("unable to add RRset %i to domain %s: already present",
            rrset->rr_type, domain->name);
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    domain->nsec_bitmap_changed = 1;
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, rrset_type* rrset)
{
    rrset_type* del_rrset = NULL;
    ldns_rbnode_t* del_node = NULL;
    char* str = NULL;

    se_log_assert(rrset);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    del_node = ldns_rbtree_delete(domain->rrsets,
        (const void*)&rrset->rr_type);
    if (del_node) {
        del_rrset = (rrset_type*) del_node->data;
        rrset_cleanup(del_rrset);
        se_free((void*)del_node);
        domain->nsec_bitmap_changed = 1;
        return NULL;
    } else {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete RRset %i from domain %s: "
            "not in tree", rrset->rr_type, domain->name);
        se_free((void*)str);
        return rrset;
    }
    return rrset;
}


/**
 * Return the number of RRsets at this domain.
 *
 */
int domain_count_rrset(domain_type* domain)
{
    se_log_assert(domain);
    if (!domain->rrsets) {
        return 0;
    }
    return domain->rrsets->count;
}


/**
 * Update domain with pending changes.
 *
 */
int
domain_update(domain_type* domain, uint32_t serial)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(serial);
    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (domain->inbound_serial < serial) {
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset_update(rrset, serial) != 0) {
                se_log_error("failed to update domain to serial %u: failed "
                    "to update RRset", serial);
                return 1;
            }
            node = ldns_rbtree_next(node);
            /* delete memory of RRsets if no RRs exist */
            if (rrset_count_rr(rrset) <= 0) {
                rrset = domain_del_rrset(domain, rrset);
            }
        }
        domain->inbound_serial = serial;
    }
    return 0;
}


/**
 * Update domain status.
 *
 */
void
domain_update_status(domain_type* domain)
{
    domain_type* parent = NULL;

    se_log_assert(domain);
    if (domain->domain_status == DOMAIN_STATUS_APEX) {
        /* apex stays apex */
        return;
    }

    if (domain_count_rrset(domain) <= 0) {
        /* Empty Non-Terminal */
        return; /* we don't care */
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        domain->domain_status = DOMAIN_STATUS_NS;
    }

    parent = domain->parent;
    while (parent) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME) ||
            domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            domain->domain_status = DOMAIN_STATUS_OCCLUDED;
            return;
        }
        parent = parent->parent;
    }
    /* else, it is just an authoritative domain */
    domain->domain_status = DOMAIN_STATUS_AUTH;
    return;
}


/**
 * Add RR to domain.
 *
 */
int
domain_add_rr(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_add_rr(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    rrset = rrset_create(ldns_rr_get_type(rr));
    rrset = domain_add_rrset(domain, rrset);
    if (!rrset) {
        se_log_error("unable to add RR to domain: failed to add RRset");
        return 1;
    }
    return rrset_add_rr(rrset, rr);
}


/**
 * Delete RR from domain.
 *
 */
int
domain_del_rr(domain_type* domain, ldns_rr* rr)
{
    rrset_type* rrset = NULL;

    se_log_assert(rr);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(domain->rrsets);
    se_log_assert((ldns_dname_compare(domain->name, ldns_rr_owner(rr)) == 0));

    rrset = domain_lookup_rrset(domain, ldns_rr_get_type(rr));
    if (rrset) {
        return rrset_del_rr(rrset, rr);
    }
    /* no RRset with this RRtype yet */
    se_log_warning("unable to delete RR from domain: no such RRset "
        "[rrtype %i]", ldns_rr_get_type(rr));
    return 0; /* well, it is not present in the zone anymore, is it? */
}


/**
 * Delete all RRs from domain.
 *
 */
int
domain_del_rrs(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    se_log_assert(domain);
    se_log_assert(domain->rrsets);

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
		if (rrset_del_rrs(rrset) != 0) {
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Clean up RRsets at the domain.
 *
 */
static void
domain_cleanup_rrsets(ldns_rbtree_t* rrset_tree)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
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
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    } else {
        se_log_warning("cleanup empty domain");
    }
    return;
}


/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain, int internal)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    char* str = NULL;

    if (internal) {
        se_log_assert(domain->name);
        str = ldns_rdf2str(domain->name);
        fprintf(fd, "; DNAME: %s\n", str);
        se_free((void*)str);
    }

    if (domain->rrsets && domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    /* print soa */
    soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
    if (soa_rrset && !internal) {
        rrset_print(fd, soa_rrset);
    }

    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset->rr_type != LDNS_RR_TYPE_SOA || internal) {
            rrset_print(fd, rrset);
        }
        node = ldns_rbtree_next(node);
    }
    return;
}
