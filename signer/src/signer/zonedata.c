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
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "signer/zonedata.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_dname_*(), ldns_rbtree_*() */


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
 * Add empty non-terminals to a domain in the zone data.
 *
 */
static int
zonedata_domain_entize(zonedata_type* zd, domain_type* domain, ldns_rdf* apex)
{
    int ent2unsigned_deleg = 0;
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;

    se_log_assert(apex);
    se_log_assert(domain);
    se_log_assert(domain->name);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    if (domain->parent) {
        /* domain already has parent */
        return 0;
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS) &&
        !domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
        /* empty non-terminal to unsigned delegation */
        ent2unsigned_deleg = 1;
    }

    while (domain && ldns_dname_compare(domain->name, apex) != 0) {
        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->name);
        if (!parent_rdf) {
            se_log_error("unable to create parent domain name (rdf)");
            return 1;
        }

        parent_domain = zonedata_lookup_domain(zd, parent_rdf);
        if (!parent_domain) {
            parent_domain = domain_create(parent_rdf);
            parent_domain = zonedata_add_domain(zd, parent_domain, 0);
            if (!parent_domain) {
                se_log_error("unable to add parent domain");
                return 1;
            }
            parent_domain->domain_status =
                (ent2unsigned_deleg?DOMAIN_STATUS_ENT_NS:
                                    DOMAIN_STATUS_ENT_AUTH);
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            domain->parent = parent_domain;
            if (domain_count_rrset(parent_domain) <= 0) {
                parent_domain->domain_status =
                    (ent2unsigned_deleg?DOMAIN_STATUS_ENT_NS:
                                        DOMAIN_STATUS_ENT_AUTH);
            }
            /* done */
            domain = NULL;
        }
    }
    return 0;
}


/**
 * Revise the empty non-terminals domain status.
 *
 */
static void
zonedata_domain_entize_revised(domain_type* domain, int status)
{
    domain_type* parent = NULL;
    if (!domain) {
        return;
    }
    parent = domain->parent;
    while (parent) {
        if (parent->domain_status == DOMAIN_STATUS_ENT_AUTH ||
            parent->domain_status == DOMAIN_STATUS_ENT_GLUE ||
            parent->domain_status == DOMAIN_STATUS_ENT_NS) {
            parent->domain_status = status;
        } else {
           break;
        }
        parent = parent->parent;
    }
    return;
}


/**
 * Add empty non-terminals to zone data.
 *
 */
int
zonedata_entize(zonedata_type* zd, ldns_rdf* apex)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    int prev_status = DOMAIN_STATUS_NONE;

    se_log_assert(apex);
    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (zonedata_domain_entize(zd, domain, apex) != 0) {
            se_log_error("error adding enmpty non-terminals to domain");
            return 1;
        }
        /* domain has parent now, check for glue */
        prev_status = domain->domain_status;
        domain_update_status(domain);
        if (domain->domain_status == DOMAIN_STATUS_OCCLUDED &&
            prev_status != DOMAIN_STATUS_OCCLUDED) {
            zonedata_domain_entize_revised(domain, DOMAIN_STATUS_ENT_GLUE);
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}

/**
 * Add NSEC records to zonedata.
 *
 */
int
zonedata_nsecify(zonedata_type* zd, ldns_rr_class klass)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL, *to = NULL, *apex = NULL;
    int have_next = 0;

    se_log_assert(zd);
    se_log_assert(zd->domains);

    node = ldns_rbtree_first(zd->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->domain_status == DOMAIN_STATUS_APEX) {
            apex = domain;
        }
        /* don't do glue-only or empty domains */
        if (domain->domain_status == DOMAIN_STATUS_OCCLUDED ||
            domain_count_rrset(domain) <= 0) {
            node = ldns_rbtree_next(node);
            continue;
        }
        node = ldns_rbtree_next(node);
        have_next = 0;
        while (!have_next) {
            if (node && node != LDNS_RBTREE_NULL) {
                to = (domain_type*) node->data;
            } else if (apex) {
                to = apex;
            } else {
                se_log_alert("apex undefined!, aborting nsecify");
                return 1;
            }
            /* don't do glue-only or empty domains */
            if (to->domain_status == DOMAIN_STATUS_OCCLUDED ||
                domain_count_rrset(to) <= 0) {
                node = ldns_rbtree_next(node);
            } else {
                have_next = 1;
            }
        }
        /* ready to add the NSEC record */
        if (domain_nsecify(domain, to, zd->default_ttl, klass) != 0) {
            se_log_error("adding NSECs to domain failed");
            return 1;
        }
    }
    return 0;
}


/**
 * Add NSEC3 records to zonedata.
 *
 */
int
zonedata_nsecify3(zonedata_type* zd, ldns_rr_class klass, nsec3params_type* nsec3params)
{
    se_log_assert(zd);

    return zonedata_nsecify(zd, klass); /* for now */
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
        /* delete memory of domain if no RRsets exists */
        if (domain_count_rrset(domain) <= 0) {
            /* also delete empty non-terminal parents: TODO (NSEC3) */
            domain = zonedata_del_domain(zd, domain);
        }
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
