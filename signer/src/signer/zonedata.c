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
 * Zone data.
 *
 */

#include "config.h"
#include "signer/zonedata.h"
#include "signer/domain.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_dname_compare(), ldns_rbtree_*() */


/**
 * Compare domains.
 *
 */
static int
domain_compare(const void* a, const void* b)
{
    ldns_rdf* x = (ldns_rdf*)a;
    ldns_rdf* y = (ldns_rdf*)b;
    return ldns_dname_compare(x, y);
}


/**
 * Create empty zone data..
 *
 */
zonedata_type*
zonedata_create(void)
{
    zonedata_type* zd = (zonedata_type*) se_malloc(sizeof(zonedata_type));
    zd->domains = ldns_rbtree_create(domain_compare);
    zd->nsec3_domains = NULL;
    zd->inbound_serial = 0;
    zd->outbound_serial = 0;
    zd->default_ttl = 3600; /* configure --default-ttl option? */
    return zd;
}


/**
 * Convert a domain to a tree node.
 *
 */
static ldns_rbnode_t*
domain2node(domain_type* domain)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) se_malloc(sizeof(ldns_rbnode_t));
    node->key = domain->name;
    node->data = domain;
    return node;
}


/**
 * Lookup domain.
 *
 */
domain_type*
zonedata_lookup_domain(zonedata_type* zd, ldns_rdf* name)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(name);

    node = ldns_rbtree_search(zd->domains, name);
    if (node && node != LDNS_RBTREE_NULL) {
        return (domain_type*) node->data;
    }
    return NULL;
}


/**
 * Add a domain to the zone data.
 *
 */
domain_type*
zonedata_add_domain(zonedata_type* zd, domain_type* domain, int at_apex)
{
    ldns_rbnode_t* new_node = NULL;
    char* str = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(domain);

    new_node = domain2node(domain);
    if (ldns_rbtree_insert(zd->domains, new_node) == NULL) {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to add domain %s: already present", domain->name);
        se_free((void*)str);
        se_free((void*)new_node);
        return NULL;
    }
    domain->domain_status = DOMAIN_STATUS_NONE;
    if (at_apex) {
        domain->domain_status = DOMAIN_STATUS_APEX;
    }
    return domain;
}


/**
 * Delete a domain from the zone data.
 *
 */
domain_type*
zonedata_del_domain(zonedata_type* zd, domain_type* domain)
{
    domain_type* del_domain = NULL;
    ldns_rbnode_t* del_node = NULL;
    char* str = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(domain);

    del_node = ldns_rbtree_delete(zd->domains, (const void*)domain->name);
    if (del_node) {
        del_domain = (domain_type*) del_node->data;
        domain_cleanup(del_domain);
        se_free((void*)del_node);
        return NULL;
    } else {
        str = ldns_rdf2str(domain->name);
        se_log_error("unable to delete domain %s: not in tree", domain->name);
        se_free((void*)str);
        return domain;
    }
    return domain;
}


/**
 * Update zone data with pending changes.
 *
 */
int
zonedata_update(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (!zd->inbound_serial) {
        se_log_error("unable to update zonedata: serial is zero");
        return 1;
    }

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain_update(domain, zd->inbound_serial) != 0) {
            se_log_error("unable to update zonedata to serial %u: failed "
                "to update domain", zd->inbound_serial);
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Add RR to the zone data.
 *
 */
int
zonedata_add_rr(zonedata_type* zd, ldns_rr* rr, int at_apex)
{
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_add_rr(domain, rr);
    }
    /* no domain with this name yet */
    domain = domain_create(ldns_rr_owner(rr));
    domain = zonedata_add_domain(zd, domain, at_apex);
    if (!domain) {
        se_log_error("unable to add RR to zonedata: failed to add domain");
        return 1;
    }
    return domain_add_rr(domain, rr);
}


/**
 * Delete RR from the zone data.
 *
 */
int
zonedata_del_rr(zonedata_type* zd, ldns_rr* rr)
{
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);
    se_log_assert(rr);

    domain = zonedata_lookup_domain(zd, ldns_rr_owner(rr));
    if (domain) {
        return domain_del_rr(domain, rr);
    }
    /* no domain with this name yet */
    se_log_warning("unable to delete RR from zonedata: no such domain");
    return 0;
}


/**
 * Delete all current RRs from the zone data.
 *
 */
int
zonedata_del_rrs(zonedata_type* zd)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (zd->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(zd->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain_del_rrs(domain) != 0) {
            return 1;
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Clean up domains in zone data.
 *
 */
static void
zonedata_cleanup_domains(ldns_rbtree_t* domain_tree)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (domain_tree && domain_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_cleanup(domain);
        node = ldns_rbtree_next(node);
    }
    se_rbnode_free(domain_tree->root);
    ldns_rbtree_free(domain_tree);
    return;
}


/**
 * Clean up zone data.
 *
 */
void
zonedata_cleanup(zonedata_type* zonedata)
{
    /* destroy domains */
    if (zonedata) {
        if (zonedata->domains) {
            zonedata_cleanup_domains(zonedata->domains);
        }
        if (zonedata->nsec3_domains) {
            zonedata_cleanup_domains(zonedata->nsec3_domains);
        }
        se_free((void*) zonedata);
    } else {
        se_log_warning("cleanup empty zone data");
    }
    return;
}


/**
 * Print zone data.
 *
 */
void
zonedata_print(FILE* fd, zonedata_type* zd, int internal)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    se_log_assert(fd);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; zone empty\n");
        return;
    }

    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(fd, domain, internal);
        node = ldns_rbtree_next(node);
    }
    return;
}
