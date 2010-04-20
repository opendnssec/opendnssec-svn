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
 * The zonelist and all.
 */

#include "config.h"
#include "signer/zone.h"
#include "signer/zonelist.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_dname_compare(), ldns_rbtree_*() */


/**
 * Compare two zones.
 *
 */
static int
zone_compare(const void* a, const void* b)
{
    zone_type* x = (zone_type*)a;
    zone_type* y = (zone_type*)b;

    se_log_assert(x);
    se_log_assert(y);

    if (x->klass != y->klass) {
        if (x->klass < y->klass) {
            return -1;
        }
        return 1;
    }
    return ldns_dname_compare(x->dname, y->dname);
}


/**
 * Create a new zone list.
 *
 */
zonelist_type*
zonelist_create(void)
{
    zonelist_type* zlist = (zonelist_type*) se_malloc(sizeof(zonelist_type));
    zlist->zones = ldns_rbtree_create(zone_compare);
    zlist->last_modified = 0;
    return zlist;
}


/**
 * Clean up a zonelist.
 *
 */
void
zonelist_cleanup(zonelist_type* zonelist)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    if (zonelist) {
        if (zonelist->zones) {
            node = ldns_rbtree_first(zonelist->zones);
            while (node != LDNS_RBTREE_NULL) {
                zone = (zone_type*) node->key;
                zone_cleanup(zone);
                node = ldns_rbtree_next(node);
            }
            se_rbnode_free(zonelist->zones->root);
            ldns_rbtree_free(zonelist->zones);
            zonelist->zones = NULL;
        }
        se_free((void*) zonelist);
    } else {
        se_log_warning("cleanup empty zone list");
    }
}
