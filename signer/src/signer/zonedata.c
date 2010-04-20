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
    return zd;
}


/**
 * Clean up domains in zone data.
 *
 */
static void
zonedata_cleanup_domains(ldns_rbtree_t* domain_tree)
{
    ldns_rbnode_t* node = NULL;
    domain_type* name = NULL;

    if (domain_tree && domain_tree->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain_tree);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        name = (domain_type*) node->data;
        domain_cleanup(name);
        node = ldns_rbtree_next(node);
    }
    se_rbnode_free(domain_tree->root);
    ldns_rbtree_free(domain_tree);
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
}
