/*
 * $Id: namedb.c 5467 2011-08-24 06:51:16Z matthijs $
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
 * Domain name database.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/domain.h"
#include "signer/nsec3params.h"
#include "signer/namedb.h"
#include "signer/zone.h"

#include <ldns/ldns.h> /* ldns_dname_*(), ldns_rbtree_*() */

const char* db_str = "namedb";

static ldns_rbnode_t* domain2node(domain_type* domain);


/**
 * Convert a domain to a tree node.
 *
 */
static ldns_rbnode_t*
domain2node(domain_type* domain)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = domain->dname;
    node->data = domain;
    return node;
}


/**
 * Convert a denial to a tree node.
 *
 */
static ldns_rbnode_t*
denial2node(denial_type* denial)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = denial->dname;
    node->data = denial;
    return node;
}


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
 * Initialize denials.
 *
 */
void
namedb_init_denials(namedb_type* db)
{
    if (db) {
        db->denials = ldns_rbtree_create(domain_compare);
    }
    return;
}


/**
 * Initialize domains.
 *
 */
static void
namedb_init_domains(namedb_type* db)
{
    if (db) {
        db->domains = ldns_rbtree_create(domain_compare);
    }
    return;
}


/**
 * Create a new namedb.
 *
 */
namedb_type*
namedb_create(void* zone)
{
    namedb_type* db = NULL;
    zone_type* z = (zone_type*) zone;

    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->allocator);
    db = (namedb_type*) allocator_alloc(z->allocator, sizeof(namedb_type));
    if (!db) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "allocator_alloc() failed", db_str, z->name);
        return NULL;
    }
    db->zone = zone;

    namedb_init_domains(db);
    if (!db->domains) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "init domains failed", db_str, z->name);
        namedb_cleanup(db);
        return NULL;
    }
    namedb_init_denials(db);
    if (!db->denials) {
        ods_log_error("[%s] unable to create namedb for zone %s: "
            "init denials failed", db_str, z->name);
        namedb_cleanup(db);
        return NULL;
    }
    db->inbserial = 0;
    db->intserial = 0;
    db->outserial = 0;
    db->is_initialized = 0;
    db->is_processed = 0;
    db->serial_updated = 0;
    return db;
}


/**
 * Recover zone data from backup.
 *
 */
ods_status
namedb_recover(namedb_type* db, FILE* fd)
{
    const char* token = NULL;
    const char* owner = NULL;
    int dstatus = 0;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    ldns_rdf* rdf = NULL;
    ldns_rbnode_t* denial_node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;

    ods_log_assert(db);
    ods_log_assert(fd);

    while (backup_read_str(fd, &token)) {
        /* domain part */
        if (ods_strcmp(token, ";;Domain:") == 0) {
            if (!backup_read_check_str(fd, "name") ||
                !backup_read_str(fd, &owner) ||
                !backup_read_check_str(fd, "status") ||
                !backup_read_int(fd, &dstatus)) {
                ods_log_error("[%s] domain in backup corrupted", db_str);
                goto recover_domain_error;
            }
            /* ok, look up domain */
            rdf = ldns_dname_new_frm_str(owner);
            if (rdf) {
                domain = namedb_lookup_domain(db, rdf);
                ldns_rdf_deep_free(rdf);
                rdf = NULL;
            }
            if (!domain) {
                ods_log_error("[%s] domain in backup, but not in namedb",
                    db_str);
                goto recover_domain_error;
            }
            /* lookup success */
            status = domain_recover(domain, fd, dstatus);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover domain", db_str);
                goto recover_domain_error;
            }
            if (domain->denial) {
                denial = (void*) domain->denial;
                denial_node = denial2node(denial);
                /* insert */
                if (!ldns_rbtree_insert(db->denials, denial_node)) {
                    ods_log_error("[%s] unable to recover denial", db_str);
                    free((void*)denial_node);
                    goto recover_domain_error;
                }
                denial->node = denial_node;
                denial_node = NULL;
            }

            /* done, next domain */
            free((void*) owner);
            owner = NULL;
            domain = NULL;
        } else if (ods_strcmp(token, ";;") == 0) {
            /* done with all zone data */
            free((void*) token);
            token = NULL;
            return ODS_STATUS_OK;
        } else {
            /* domain corrupted */
            ods_log_error("[%s] domain in backup corrupted", db_str);
            goto recover_domain_error;
        }
        free((void*) token);
        token = NULL;
    }

    if (!backup_read_check_str(fd, ODS_SE_FILE_MAGIC)) {
        goto recover_domain_error;
    }

    return ODS_STATUS_OK;

recover_domain_error:
    free((void*) owner);
    owner = NULL;

    free((void*) token);
    token = NULL;

    return ODS_STATUS_ERR;
}


/**
 * Internal lookup domain function.
 *
 */
static void*
namedb_domain_search(ldns_rbtree_t* tree, ldns_rdf* dname)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (!tree || !dname) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, dname);
    if (node && node != LDNS_RBTREE_NULL) {
        return (void*) node->data;
    }
    return NULL;
}


/**
 * Determine new SOA SERIAL.
 *
 */
ods_status
namedb_update_serial(namedb_type* db, const char* format, uint32_t serial)
{
    uint32_t soa = 0;
    uint32_t prev = 0;
    uint32_t update = 0;
    if (!db || !format) {
        return ODS_STATUS_ASSERT_ERR;
    }
    prev = db->outserial;
    if (!db->is_initialized) {
        prev = serial;
    }
    ods_log_debug("[%s] update serial: format=%s "
        "in=%u internal=%u out=%u now=%u",
        db_str, format, db->inbserial, db->intserial, db->outserial,
        (uint32_t) time_now());

    if (ods_strcmp(format, "unixtime") == 0) {
        soa = (uint32_t) time_now();
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "datecounter") == 0) {
        soa = (uint32_t) time_datestamp(0, "%Y%m%d", NULL) * 100;
        if (!DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "counter") == 0) {
        soa = serial;
        if (db->is_initialized && !DNS_SERIAL_GT(soa, prev)) {
            soa = prev + 1;
        }
    } else if (ods_strcmp(format, "keep") == 0) {
        soa = serial;
        if (db->is_initialized && !DNS_SERIAL_GT(soa, prev)) {
            ods_log_error("[%s] cannot keep SOA SERIAL from input zone "
                " (%u): previous output SOA SERIAL is %u", db_str, soa, prev);
            return ODS_STATUS_CONFLICT_ERR;
        }
    } else {
        ods_log_error("[%s] unknown serial type %s", db_str, format);
        return ODS_STATUS_ERR;
    }
    /* serial is stored in 32 bits */
    update = soa - prev;
    if (update > 0x7FFFFFFF) {
        update = 0x7FFFFFFF;
    }
    if (!db->is_initialized) {
        db->intserial = soa;
    } else {
        db->intserial += update; /* automatically does % 2^32 */
    }
    ods_log_debug("[%s] update serial: %u + %u = %u", db_str, prev, update,
        db->intserial);
    return ODS_STATUS_OK;
}


/**
 * Lookup domain.
 *
 */
domain_type*
namedb_lookup_domain(namedb_type* db, ldns_rdf* dname)
{
    if (!db) {
        return NULL;
    }
    return (domain_type*) namedb_domain_search(db->domains, dname);
}


/**
 * Add domain to namedb.
 *
 */
domain_type*
namedb_add_domain(namedb_type* db, ldns_rdf* dname)
{
    domain_type* domain = NULL;
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    if (!dname || !db || !db->domains) {
        return NULL;
    }
    domain = domain_create(db->zone, dname);
    if (!domain) {
        ods_log_error("[%s] unable to add domain: domain_create() failed",
            db_str);
        return NULL;
    }
    new_node = domain2node(domain);
    if (ldns_rbtree_insert(db->domains, new_node) == NULL) {
        ods_log_error("[%s] unable to add domain: already present", db_str);
        log_dname(domain->dname, "ERR +DOMAIN", LOG_ERR);
        domain_cleanup(domain);
        free((void*)new_node);
        return NULL;
    }
    domain = (domain_type*) new_node->data;
    domain->node = new_node;
    domain->is_new = 1;
    log_dname(domain->dname, "+DOMAIN", LOG_DEBUG);
    return domain;
}


/**
 * Delete domain from namedb
 *
 */
domain_type*
namedb_del_domain(namedb_type* db, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    if (!domain || !db || !db->domains) {
        ods_log_error("[%s] unable to delete domain: !db || !domain", db_str);
        log_dname(domain->dname, "ERR -DOMAIN", LOG_ERR);
        return NULL;
    }
    if (domain->rrsets || domain->denial) {
        ods_log_error("[%s] unable to delete domain: domain in use", db_str);
        log_dname(domain->dname, "ERR -DOMAIN", LOG_ERR);
        return NULL;
    }
    node = ldns_rbtree_delete(db->domains, (const void*)domain->dname);
    if (node) {
        ods_log_assert(domain->node == node);
        ods_log_assert(!domain->rrsets);
        ods_log_assert(!domain->denial);
        free((void*)node);
        domain->node = NULL;
        log_dname(domain->dname, "-DOMAIN", LOG_DEBUG);
        return domain;
    }
    ods_log_error("[%s] unable to delete domain: not found", db_str);
    log_dname(domain->dname, "ERR -DOMAIN", LOG_ERR);
    return NULL;
}


/**
 * Internal function to lookup denial of existence data point.
 *
 */
static denial_type*
namedb_denial_search(ldns_rbtree_t* tree, ldns_rdf* dname)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !dname) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, dname);
    if (node && node != LDNS_RBTREE_NULL) {
        return (denial_type*) node->data;
    }
    return NULL;
}


/**
 * Lookup denial of existence data point.
 *
 */
denial_type*
namedb_lookup_denial(namedb_type* db, ldns_rdf* dname)
{
    if (!db) return NULL;

    return namedb_denial_search(db->denials, dname);
}


/**
 * Provide domain with NSEC3 hashed domain.
 *
 */
static ldns_rdf*
dname_hash(ldns_rdf* dname, ldns_rdf* apex, nsec3params_type* nsec3params)
{
    ldns_rdf* hashed_ownername = NULL;
    ldns_rdf* hashed_label = NULL;

    ods_log_assert(dname);
    ods_log_assert(apex);
    ods_log_assert(nsec3params);

    /**
     * The owner name of the NSEC3 RR is the hash of the original owner
     * name, prepended as a single label to the zone name.
     */
    hashed_label = ldns_nsec3_hash_name(dname, nsec3params->algorithm,
        nsec3params->iterations, nsec3params->salt_len,
        nsec3params->salt_data);
    if (!hashed_label) {
        log_dname(dname, "unable to hash dname, hash failed", LOG_ERR);
        return NULL;
    }
    hashed_ownername = ldns_dname_cat_clone((const ldns_rdf*) hashed_label,
        (const ldns_rdf*) apex);
    if (!hashed_ownername) {
        log_dname(dname, "unable to hash dname, concat apex failed", LOG_ERR);
        return NULL;
    }
    ldns_rdf_deep_free(hashed_label);
    return hashed_ownername;
}


/**
 * Add denial of existence data point to the zone data.
 *
 */
ods_status
namedb_add_denial(namedb_type* db, domain_type* domain, ldns_rdf* apex,
    nsec3params_type* nsec3params)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rdf* owner = NULL;
    denial_type* denial = NULL;
    denial_type* prev_denial = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to add denial of existence data point: "
            "no domain", db_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(domain);

    if (!db || !db->denials) {
        log_dname(domain->dname, "unable to add denial of existence data "
            "point for domain, no denial chain", LOG_ERR);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(db);
    ods_log_assert(db->denials);

    if (!apex) {
        log_dname(domain->dname, "unable to add denial of existence data "
            "point for domain, apex unknown", LOG_ERR);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(apex);

    /* nsec or nsec3 */
    if (nsec3params) {
        owner = dname_hash(domain->dname, apex, nsec3params);
        if (!owner) {
            log_dname(domain->dname, "unable to add denial of existence data "
                "point for domain, dname hash failed", LOG_ERR);
            return ODS_STATUS_ERR;
        }
    } else {
        owner = ldns_rdf_clone(domain->dname);
    }
    /* lookup */
    if (namedb_lookup_denial(db, owner) != NULL) {
        log_dname(domain->dname, "unable to add denial of existence for "
            "domain, data point exists", LOG_ERR);
        return ODS_STATUS_CONFLICT_ERR;
    }
    /* create */
    denial = denial_create(db->zone, owner);
    new_node = denial2node(denial);
    ldns_rdf_deep_free(owner);
    /* insert */
    if (!ldns_rbtree_insert(db->denials, new_node)) {
        log_dname(domain->dname, "unable to add denial of existence for "
            "domain, insert failed", LOG_ERR);
        free((void*)new_node);
        denial_cleanup(denial);
        return ODS_STATUS_ERR;
    }
    /* denial of existence data point added */
    denial->bitmap_changed = 1;
    denial->nxt_changed = 1;
    prev_node = ldns_rbtree_previous(new_node);
    if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
        prev_node = ldns_rbtree_last(db->denials);
    }
    ods_log_assert(prev_node);
    prev_denial = (denial_type*) prev_node->data;
    ods_log_assert(prev_denial);
    prev_denial->nxt_changed = 1;
    domain->denial = (void*) denial;
    denial->domain = (void*) domain; /* back reference */
    return ODS_STATUS_OK;
}


/**
 * Internal delete denial function.
 *
 */
static denial_type*
namedb_del_denial_fixup(ldns_rbtree_t* tree, denial_type* denial)
{
    denial_type* del_denial = NULL;
    denial_type* prev_denial = NULL;
    ldns_rbnode_t* prev_node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;

    ods_log_assert(tree);
    ods_log_assert(denial);
    ods_log_assert(denial->dname);

    del_node = ldns_rbtree_search(tree, (const void*)denial->dname);
    if (del_node) {
        /**
         * [CALC] if domain removed, mark prev domain NSEC(3) nxt changed.
         *
         */
        prev_node = ldns_rbtree_previous(del_node);
        if (!prev_node || prev_node == LDNS_RBTREE_NULL) {
            prev_node = ldns_rbtree_last(tree);
        }
        ods_log_assert(prev_node);
        ods_log_assert(prev_node->data);
        prev_denial = (denial_type*) prev_node->data;
        prev_denial->nxt_changed = 1;

        /* delete old NSEC RR(s) */
        rrset_diff(denial->rrset);
        del_node = ldns_rbtree_delete(tree, (const void*)denial->dname);
        del_denial = (denial_type*) del_node->data;
        denial_cleanup(del_denial);
        free((void*)del_node);
        return NULL;
    } else {
        log_dname(denial->dname, "unable to del denial of existence data "
            "point, not found", LOG_ERR);
    }
    return denial;
}


/**
 * Delete denial of existence data point from the zone data.
 *
 */
denial_type*
namedb_del_denial(namedb_type* db, denial_type* denial)
{
    if (!denial) {
        ods_log_error("[%s] unable to delete denial of existence data "
            "point: no data point", db_str);
        return NULL;
    }
    ods_log_assert(denial);

    if (!db || !db->denials) {
        log_dname(denial->dname, "unable to delete denial of existence data "
            "point, no db", LOG_ERR);
        return denial;
    }
    ods_log_assert(db);
    ods_log_assert(db->denials);

    return namedb_del_denial_fixup(db->denials, denial);
}


/**
 * Calculate differences at the namedb between current and new RRsets.
 *
 */
void
namedb_diff(namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!db || !db->domains) {
        return;
    }
    if (db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_diff(domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Rollback updates from zone data.
 *
 */
void
namedb_rollback(namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!db || !db->domains) {
        return;
    }
    if (db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_rollback(domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Add empty non-terminals to zone data from this domain up.
 *
 */
static ods_status
domain_entize(namedb_type* db, domain_type* domain, ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    domain_type* parent_domain = NULL;

    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(db);
    ods_log_assert(db->domains);

    if (domain->parent) {
        /* domain already has parent */
        return ODS_STATUS_OK;
    }

    while (domain && ldns_dname_is_subdomain(domain->dname, apex) &&
           ldns_dname_compare(domain->dname, apex) != 0) {

        /**
         * RFC5155:
         * 4. If the difference in number of labels between the apex and
         *    the original owner name is greater than 1, additional NSEC3
         *    RRs need to be added for every empty non-terminal between
         *     the apex and the original owner name.
         */
        parent_rdf = ldns_dname_left_chop(domain->dname);
        if (!parent_rdf) {
            log_dname(domain->dname, "unable to entize domain, left chop "
                "failed", LOG_ERR);
            return ODS_STATUS_ERR;
        }
        ods_log_assert(parent_rdf);

        parent_domain = namedb_lookup_domain(db, parent_rdf);
        if (!parent_domain) {
            if (namedb_add_domain(db, parent_rdf) == NULL) {
                log_dname(domain->dname, "unable to entize domain, add parent "
                    "failed", LOG_ERR);
                domain_cleanup(parent_domain);
                return ODS_STATUS_ERR;
            }
            domain->parent = parent_domain;
            /* continue with the parent domain */
            domain = parent_domain;
        } else {
            ldns_rdf_deep_free(parent_rdf);
            domain->parent = parent_domain;
            /* we are done with this domain */
            domain = NULL;
        }
    }
    return ODS_STATUS_OK;
}


/**
 * Add empty non-terminals to zone data.
 *
 */
ods_status
namedb_entize(namedb_type* db, ldns_rdf* apex)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;

    if (!db || !db->domains) {
        ods_log_error("[%s] unable to entize zone data: no zone data",
            db_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(db);
    ods_log_assert(db->domains);

    if (!apex) {
        ods_log_error("[%s] unable to entize zone data: no zone apex",
            db_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(apex);

    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_entize(db, domain, apex);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to entize zone data: entize domain "
                "failed", db_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return ODS_STATUS_OK;
}


/**
 * Add NSEC records to namedb.
 *
 */
ods_status
namedb_nsecify(namedb_type* db, ldns_rr_class klass, uint32_t ttl,
    uint32_t* num_added)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    size_t nsec_added = 0;
    ldns_rr_type occluded = LDNS_RR_TYPE_SOA;
    ldns_rr_type delegpt = LDNS_RR_TYPE_SOA;

    if (!db || !db->domains) {
        return ODS_STATUS_OK;
    }
    ods_log_assert(db);
    ods_log_assert(db->domains);

    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->is_apex) {
            apex = domain;
        }
        occluded = domain_is_occluded(domain);
        delegpt = domain_is_delegpt(domain);

        /* don't do glue-only or empty domains */
        if (occluded != LDNS_RR_TYPE_SOA ||
            domain_count_rrset(domain) <= 0) {
            if (domain_count_rrset(domain)) {
                log_dname(domain->dname, "nsecify: don't do glue domain",
                    LOG_DEEEBUG);
            } else {
                log_dname(domain->dname, "nsecify: don't do empty domain",
                    LOG_DEEEBUG);
            }
            if (domain->denial) {
                if (namedb_del_denial(db, domain->denial) != NULL) {
                    ods_log_warning("[%s] unable to nsecify: failed to "
                        "delete denial of existence data point", db_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify: apex unknown", db_str);
            return ODS_STATUS_ASSERT_ERR;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            status = namedb_add_denial(db, domain, apex->dname, NULL);
            if (status != ODS_STATUS_OK) {
                log_dname(domain->dname, "unable to nsecify: failed to add "
                    "denial of existence for domain", LOG_ERR);
                return status;
            }
            nsec_added++;
        }
        node = ldns_rbtree_next(node);
    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(db->denials);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(db->denials);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify(denial, nxt, ttl, klass);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify: failed to add NSEC record",
                db_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    if (num_added) {
        *num_added = nsec_added;
    }
    return ODS_STATUS_OK;
}


/**
 * Add NSEC3 records to namedb.
 *
 */
ods_status
namedb_nsecify3(namedb_type* db, ldns_rr_class klass,
    uint32_t ttl, nsec3params_type* nsec3params, uint32_t* num_added)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    ldns_rbnode_t* nxt_node = LDNS_RBTREE_NULL;
    ods_status status = ODS_STATUS_OK;
    domain_type* domain = NULL;
    domain_type* apex = NULL;
    denial_type* denial = NULL;
    denial_type* nxt = NULL;
    size_t nsec3_added = 0;
    ldns_rr_type occluded = LDNS_RR_TYPE_SOA;
    ldns_rr_type delegpt = LDNS_RR_TYPE_SOA;

    if (!db || !db->domains) {
        return ODS_STATUS_OK;
    }
    ods_log_assert(db);
    ods_log_assert(db->domains);

    if (!nsec3params) {
        ods_log_error("[%s] unable to nsecify3: no nsec3 paramaters", db_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(nsec3params);

    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        if (domain->is_apex) {
            apex = domain;
        }
        occluded = domain_is_occluded(domain);
        delegpt = domain_is_delegpt(domain);

        /* don't do glue-only domains */
        if (occluded != LDNS_RR_TYPE_SOA) {
            log_dname(domain->dname, "nsecify3: don't do glue domain",
                LOG_DEEEBUG);
            if (domain->denial) {
                if (namedb_del_denial(db, domain->denial) != NULL) {
                    ods_log_error("[%s] unable to nsecify3: failed to "
                        "delete denial of existence data point", db_str);
                    return ODS_STATUS_ERR;
                }
            }
            node = ldns_rbtree_next(node);
            continue;
        }
        /* Opt-Out? */
        if (nsec3params->flags) {
            /* If Opt-Out is being used, owner names of unsigned delegations
               MAY be excluded. */
            if (delegpt != LDNS_RR_TYPE_SOA ||
                domain_ent2unsignedns(domain)) {
                if (delegpt != LDNS_RR_TYPE_SOA) {
                    log_dname(domain->dname, "nsecify3: opt-out (unsigned "
                        "delegation)", LOG_DEBUG);
                } else {
                    log_dname(domain->dname, "nsecify3: opt-out (empty "
                        "non-terminal (to unsigned delegation))", LOG_DEBUG);
                }
                if (domain->denial) {
                    if (namedb_del_denial(db, domain->denial) != NULL) {
                        ods_log_error("[%s] unable to nsecify3: failed to "
                            "delete denial of existence data point", db_str);
                        return ODS_STATUS_ERR;
                    }
                }
                node = ldns_rbtree_next(node);
                continue;
            }
        }
        if (!apex) {
            ods_log_alert("[%s] unable to nsecify3: apex unknown", db_str);
            return ODS_STATUS_ASSERT_ERR;
        }

        /* add the denial of existence */
        if (!domain->denial) {
            status = namedb_add_denial(db, domain, apex->dname,
                nsec3params);
            if (status != ODS_STATUS_OK) {
                log_dname(domain->dname, "unable to nsecify3: failed to add "
                    "denial of existence for domain", LOG_ERR);
                return status;
            }
            nsec3_added++;
        }

        /* The Next Hashed Owner Name field is left blank for the moment. */

        /**
         * Additionally, for collision detection purposes, optionally
         * create an additional NSEC3 RR corresponding to the original
         * owner name with the asterisk label prepended (i.e., as if a
         * wildcard existed as a child of this owner name) and keep track
         * of this original owner name. Mark this NSEC3 RR as temporary.
        **/
        /* [TODO] */
        /**
         * pseudo:
         * wildcard_name = *.domain->dname;
         * hashed_ownername = ldns_nsec3_hash_name(domain->dname,
               nsec3params->algorithm, nsec3params->iterations,
               nsec3params->salt_len, nsec3params->salt);
         * domain->nsec3_wildcard = denial_create(hashed_ownername);
        **/

        node = ldns_rbtree_next(node);
    }

    /** Now we have the complete denial of existence chain */
    node = ldns_rbtree_first(db->denials);
    while (node && node != LDNS_RBTREE_NULL) {
        denial = (denial_type*) node->data;
        nxt_node = ldns_rbtree_next(node);
        if (!nxt_node || nxt_node == LDNS_RBTREE_NULL) {
             nxt_node = ldns_rbtree_first(db->denials);
        }
        nxt = (denial_type*) nxt_node->data;

        status = denial_nsecify3(denial, nxt, ttl, klass, nsec3params);
        if (status != ODS_STATUS_OK) {
            ods_log_error("[%s] unable to nsecify3: failed to add NSEC3 "
                "record", db_str);
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    if (num_added) {
        *num_added = nsec3_added;
    }
    return ODS_STATUS_OK;
}


/**
 * Queue all RRsets.
 *
 */
ods_status
namedb_queue(namedb_type* db, fifoq_type* q, worker_type* worker)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!db || !db->domains) {
        return ODS_STATUS_OK;
    }
    if (db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        status = domain_queue(domain, q, worker);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Examine domain for occluded data.
 *
 */
static int
namedb_examine_domain_is_occluded(namedb_type* db, domain_type* domain,
    ldns_rdf* apex)
{
    ldns_rdf* parent_rdf = NULL;
    ldns_rdf* next_rdf = NULL;
    domain_type* parent_domain = NULL;
    char* str_name = NULL;
    char* str_parent = NULL;

    ods_log_assert(apex);
    ods_log_assert(domain);
    ods_log_assert(domain->dname);
    ods_log_assert(db);
    ods_log_assert(db->domains);

    if (ldns_dname_compare(domain->dname, apex) == 0) {
        return 0;
    }

    if (domain_examine_valid_zonecut(domain) != 0) {
        log_dname(domain->dname, "occluded (non-glue non-DS) data at NS",
            LOG_WARNING);
        return 1;
    }

    parent_rdf = ldns_dname_left_chop(domain->dname);
    while (parent_rdf && ldns_dname_is_subdomain(parent_rdf, apex) &&
           ldns_dname_compare(parent_rdf, apex) != 0) {

        parent_domain = namedb_lookup_domain(db, parent_rdf);
        next_rdf = ldns_dname_left_chop(parent_rdf);
        ldns_rdf_deep_free(parent_rdf);

        if (parent_domain) {
            /* check for DNAME or NS */
            if (domain_examine_data_exists(parent_domain, LDNS_RR_TYPE_DNAME,
                0) && domain_examine_data_exists(domain, 0, 0)) {
                /* data below DNAME */
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded data at %s (below %s DNAME)",
                    db_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) &&
                domain_examine_data_exists(domain, 0, 1)) {
                /* data (non-glue) below NS */
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded (non-glue) data at %s (below "
                    "%s NS)", db_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
/* allow for now (root zone has it)
            } else if (domain_examine_data_exists(parent_domain,
                LDNS_RR_TYPE_NS, 0) &&
                domain_examine_data_exists(domain, 0, 0) &&
                !domain_examine_ns_rdata(parent_domain, domain->dname)) {
                str_name = ldns_rdf2str(domain->dname);
                str_parent = ldns_rdf2str(parent_domain->dname);
                ods_log_warning("[%s] occluded data at %s (below %s NS)",
                    db_str, str_name, str_parent);
                free((void*)str_name);
                free((void*)str_parent);
                return 1;
*/
            }
        }
        parent_rdf = next_rdf;
    }
    if (parent_rdf) {
        ldns_rdf_deep_free(parent_rdf);
    }
    return 0;
}


/**
 * Examine updates to zone data.
 *
 */
ods_status
namedb_examine(namedb_type* db, ldns_rdf* apex, adapter_mode mode)
{
    int result = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!db || !db->domains) {
       /* no db, no error */
       return ODS_STATUS_OK;
    }
    ods_log_assert(db);
    ods_log_assert(db->domains);

    if (db->domains->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(db->domains);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        result =
        /* Thou shall not have other data next to CNAME */
        domain_examine_rrset_is_alone(domain, LDNS_RR_TYPE_CNAME) &&
        /* Thou shall have at most one CNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_CNAME) &&
        /* Thou shall have at most one DNAME per name */
        domain_examine_rrset_is_singleton(domain, LDNS_RR_TYPE_DNAME);
        if (!result) {
            status = ODS_STATUS_ERR;
        }

        if (mode == ADAPTER_FILE) {
            result =
            /* Thou shall not have occluded data in your zone file */
            namedb_examine_domain_is_occluded(db, domain, apex);
            if (result) {
                ; /* just warn if there is occluded data */
            }
        }
        node = ldns_rbtree_next(node);
    }
    return status;
}


/**
 * Wipe out all NSEC RRsets.
 *
 */
void
namedb_wipe_denial(namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    denial_type* denial = NULL;

    if (db && db->denials) {
        node = ldns_rbtree_first(db->denials);
        while (node && node != LDNS_RBTREE_NULL) {
            denial = (denial_type*) node->data;
            if (denial->rrset) {
                /* [TODO] IXFR delete NSEC */
                rrset_cleanup(denial->rrset);
                denial->rrset = NULL;
            }
            node = ldns_rbtree_next(node);
        }
    }
    return;
}


/**
 * Export db to file.
 *
 */
void
namedb_export(FILE* fd, namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;
    if (!fd || !db || !db->domains) {
        return;
    }
    node = ldns_rbtree_first(db->domains);
    if (!node || node == LDNS_RBTREE_NULL) {
        fprintf(fd, "; empty zone\n");
        return;
    }
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_print(fd, domain);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Clean up domains in zone data.
 *
 */
static void
domain_delfunc(ldns_rbnode_t* elem)
{
    domain_type* domain = NULL;

    if (elem && elem != LDNS_RBTREE_NULL) {
        domain = (domain_type*) elem->data;
        domain_delfunc(elem->left);
        domain_delfunc(elem->right);

        domain_cleanup(domain);
        free((void*)elem);
    }
    return;
}


/**
 * Clean up denial of existence data points from zone data.
 *
 */
static void
denial_delfunc(ldns_rbnode_t* elem)
{
    denial_type* denial = NULL;
    domain_type* domain = NULL;


    if (elem && elem != LDNS_RBTREE_NULL) {
        denial = (denial_type*) elem->data;
        denial_delfunc(elem->left);
        denial_delfunc(elem->right);

        domain = denial->domain;
        if (domain) {
            domain->denial = NULL;
        }
        denial_cleanup(denial);

        free((void*)elem);
    }
    return;
}


/**
 * Clean up domains.
 *
 */
static void
namedb_cleanup_domains(namedb_type* db)
{
    if (db && db->domains) {
        domain_delfunc(db->domains->root);
        ldns_rbtree_free(db->domains);
        db->domains = NULL;
    }
    return;
}


/**
 * Clean up denials.
 *
 */
void
namedb_cleanup_chain(namedb_type* db)
{
    if (db && db->denials) {
        denial_delfunc(db->denials->root);
        ldns_rbtree_free(db->denials);
        db->denials = NULL;
    }
    return;
}


/**
 * Clean up namedb.
 *
 */
void
namedb_cleanup(namedb_type* db)
{
    zone_type* z = NULL;
    if (!db) {
        return;
    }
    z = (zone_type*) db->zone;
    namedb_cleanup_chain(db);
    namedb_cleanup_domains(db);
    allocator_deallocate(z->allocator, (void*) db);
    return;
}


/**
 * Backup zone data.
 *
 */
void
namedb_backup(FILE* fd, namedb_type* db)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    domain_type* domain = NULL;

    if (!fd || !db) {
        return;
    }

    node = ldns_rbtree_first(db->domains);
    while (node && node != LDNS_RBTREE_NULL) {
        domain = (domain_type*) node->data;
        domain_backup(fd, domain);
        node = ldns_rbtree_next(node);
    }
    fprintf(fd, ";;\n");
    return;
}
