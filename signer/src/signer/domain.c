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
#include "shared/duration.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/backup.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/rrset.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* dname_str = "domain";


/**
 * Log domain name.
 *
 */
void
log_dname(ldns_rdf *rdf, const char* pre, int level)
{
    char* str = NULL;
    if (ods_log_get_level() < level) {
        return;
    }
    str = ldns_rdf2str(rdf);
    if (!str) {
        return;
    }
    if (level == LOG_EMERG) {
        ods_fatal_exit("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_ALERT) {
        ods_log_alert("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_CRIT) {
        ods_log_crit("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_ERR) {
        ods_log_error("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_WARNING) {
        ods_log_warning("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_NOTICE) {
        ods_log_info("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_INFO) {
        ods_log_verbose("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_DEBUG) {
        ods_log_debug("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else if (level == LOG_DEEEBUG) {
        ods_log_deeebug("[%s] %s: %s", dname_str, pre?pre:"", str);
    } else {
        ods_log_deeebug("[%s] %s: %s", dname_str, pre?pre:"", str);
    }
    free((void*)str);
    return;
}


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
 * Create domain.
 *
 */
domain_type*
domain_create(void* zoneptr, ldns_rdf* dname)
{
    domain_type* domain = NULL;
    zone_type* zone = (zone_type*) zoneptr;

    if (!dname || !zoneptr) {
        return NULL;
    }
    domain = (domain_type*) allocator_alloc(
        zone->allocator, sizeof(domain_type));
    if (!domain) {
        ods_log_error("[%s] unable to create domain: allocator_alloc() "
            "failed", dname_str);
        return NULL;
    }
    domain->dname = ldns_rdf_clone(dname);
    if (!domain->dname) {
        ods_log_error("[%s] unable to create domain: ldns_rdf_clone() "
            "failed", dname_str);
        allocator_deallocate(zone->allocator, domain);
        return NULL;
    }
    domain->zone = zoneptr;
    domain->denial = NULL; /* no reference yet */
    domain->dstatus = DOMAIN_STATUS_NONE;
    domain->parent = NULL;
    domain->rrsets = ldns_rbtree_create(rrset_compare);
    return domain;
}


/**
 * Recover domain from backup.
 *
 */
ods_status
domain_recover(domain_type* domain, FILE* fd, domain_status dstatus)
{
    const char* token = NULL;
    const char* locator = NULL;
    uint32_t flags = 0;
    ldns_rr* rr = NULL;
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    ldns_status lstatus = LDNS_STATUS_OK;
    ldns_rr_type type_covered = LDNS_RR_TYPE_FIRST;

    ods_log_assert(domain);
    ods_log_assert(fd);

    domain->dstatus = dstatus;

    while (backup_read_str(fd, &token)) {
        if (ods_strcmp(token, ";;RRSIG") == 0) {
            /* recover signature */
            if (!backup_read_str(fd, &locator) ||
                !backup_read_uint32_t(fd, &flags)) {
                ods_log_error("[%s] signature in backup corrupted",
                    dname_str);
                goto recover_dname_error;
            }
            /* expect signature */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing signature in backup", dname_str);
                ods_log_error("[%s] ldns status: %s", dname_str,
                    ldns_get_errorstr_by_id(lstatus));
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
                ods_log_error("[%s] expecting signature in backup", dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }

            type_covered = ldns_rdf2rr_type(ldns_rr_rrsig_typecovered(rr));
            rrset = domain_lookup_rrset(domain, type_covered);
            if (!rrset) {
                ods_log_error("[%s] signature type %i not covered",
                    dname_str, type_covered);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            ods_log_assert(rrset);
            if (rrset_recover(rrset, rr, locator, flags) != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover signature", dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* signature done */
            free((void*) locator);
            locator = NULL;
            rr = NULL;
        } else if (ods_strcmp(token, ";;Denial") == 0) {
            /* expect nsec(3) record */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing denial in backup", dname_str);
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC &&
                ldns_rr_get_type(rr) != LDNS_RR_TYPE_NSEC3) {
                ods_log_error("[%s] expecting denial in backup", dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }

            /* recover denial structure */
            ods_log_assert(!domain->denial);
            denial = denial_create(domain->zone, ldns_rr_owner(rr));
            ods_log_assert(denial);
            denial->domain = (void*) domain; /* back reference */
            domain->denial = (void*) denial;
            /* add the NSEC(3) rr */
            if (!denial->rrset) {
                denial->rrset = rrset_create(domain->zone,
                    ldns_rr_get_type(rr));
            }
            ods_log_assert(denial->rrset);

            if (!rrset_add_rr(denial->rrset, rr)) {
                ods_log_error("[%s] unable to recover denial", dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* commit */
            if (rrset_commit(denial->rrset) != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover denial", dname_str);
                goto recover_dname_error;
            }
            /* denial done */
            rr = NULL;

            /* recover signature */
            if (!backup_read_check_str(fd, ";;RRSIG") ||
                !backup_read_str(fd, &locator) ||
                !backup_read_uint32_t(fd, &flags)) {
                ods_log_error("[%s] signature in backup corrupted (denial)",
                    dname_str);
                goto recover_dname_error;
            }
            /* expect signature */
            lstatus = ldns_rr_new_frm_fp(&rr, fd, NULL, NULL, NULL);
            if (lstatus != LDNS_STATUS_OK) {
                ods_log_error("[%s] missing signature in backup (denial)",
                    dname_str);
                ods_log_error("[%s] ldns status: %s", dname_str,
                    ldns_get_errorstr_by_id(lstatus));
                goto recover_dname_error;
            }
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
                ods_log_error("[%s] expecting signature in backup (denial)",
                    dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            if (!denial->rrset) {
                ods_log_error("[%s] signature type not covered (denial)",
                    dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            ods_log_assert(denial->rrset);
            if (rrset_recover(denial->rrset, rr, locator, flags) !=
                ODS_STATUS_OK) {
                ods_log_error("[%s] unable to recover signature (denial)",
                    dname_str);
                ldns_rr_free(rr);
                goto recover_dname_error;
            }
            /* signature done */
            free((void*) locator);
            locator = NULL;
            rr = NULL;
        } else if (ods_strcmp(token, ";;Domaindone") == 0) {
            /* domain done */
            free((void*) token);
            token = NULL;
            break;
        } else {
            /* domain corrupted */
            goto recover_dname_error;
        }
        /* done, next token */
        free((void*) token);
        token = NULL;
    }

    return ODS_STATUS_OK;

recover_dname_error:
    free((void*) token);
    token = NULL;

    free((void*) locator);
    locator = NULL;
    return ODS_STATUS_ERR;
}


/**
 * Convert RRset to a tree node.
 *
 */
static ldns_rbnode_t*
rrset2node(rrset_type* rrset)
{
    ldns_rbnode_t* node = (ldns_rbnode_t*) malloc(sizeof(ldns_rbnode_t));
    if (!node) {
        return NULL;
    }
    node->key = (const void*) &(rrset->rrtype);
    node->data = rrset;
    return node;
}


/**
 * Internal lookup RRset function.
 *
 */
static rrset_type*
domain_rrset_search(ldns_rbtree_t* tree, ldns_rr_type rrtype)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;

    if (!tree || !rrtype) {
        return NULL;
    }
    node = ldns_rbtree_search(tree, (const void*) &rrtype);
    if (node && node != LDNS_RBTREE_NULL) {
        return (rrset_type*) node->data;
    }
    return NULL;
}


/**
 * Look up RRset at this domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    if (!domain || !rrtype) {
        return NULL;
    }
    return domain_rrset_search(domain->rrsets, rrtype);
}


/**
 * Add RRset to domain.
 *
 */
rrset_type*
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* new_node = LDNS_RBTREE_NULL;

    if (!rrset) {
        ods_log_error("[%s] unable to add RRset: no RRset", dname_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (!domain || !domain->rrsets) {
        ods_log_error("[%s] unable to add RRset: no storage", dname_str);
        return NULL;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->rrsets);

    new_node = rrset2node(rrset);
    if (ldns_rbtree_insert(domain->rrsets, new_node) == NULL) {
        ods_log_error("[%s] unable to add RRset: already present", dname_str);
        free((void*)new_node);
        return NULL;
    }
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, rrset_type* rrset)
{
    ldns_rbnode_t* del_node = LDNS_RBTREE_NULL;
    rrset_type* del_rrset = NULL;

    if (!rrset) {
        ods_log_error("[%s] unable to delete RRset: no RRset", dname_str);
        return NULL;
    }
    ods_log_assert(rrset);

    if (!domain || !domain->rrsets) {
        ods_log_error("[%s] unable to delete RRset: no storage", dname_str);
        return rrset;
    }
    ods_log_assert(domain);
    ods_log_assert(domain->rrsets);

    del_node = ldns_rbtree_search(domain->rrsets,
        (const void*) &(rrset->rrtype));
    if (del_node) {
        del_node = ldns_rbtree_delete(domain->rrsets,
            (const void*) &(rrset->rrtype));
        del_rrset = (rrset_type*) del_node->data;
        rrset_cleanup(del_rrset);
        free((void*)del_node);
        return NULL;
    }
    return rrset;
}


/**
 * Count the number of RRsets at this domain.
 *
 */
size_t
domain_count_rrset(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain || !domain->rrsets) {
        return 0;
    }

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset_count_rr(rrset, COUNT_RR) > 0) {
            count++;
        }
        node = ldns_rbtree_next(node);
    }
    return count;
}


/**
 * Apply differences at domain.
 *
 */
void
domain_diff(domain_type* domain, keylist_type* kl)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (!domain || !domain->rrsets) {
        return;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        /* special cases */
        if (rrset->rrtype == LDNS_RR_TYPE_NSEC3PARAMS) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* normal cases */
        rrset_diff(rrset, kl);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Examine domain and verify if data exists.
 *
 */
int
domain_examine_data_exists(domain_type* domain, ldns_rr_type rrtype,
    int skip_glue)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (!domain) {
        return 0;
    }
    ods_log_assert(domain);

    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        if (rrset_count_RR(rrset) > 0) {
            if (rrtype) {
                /* looking for a specific RRset */
                if (rrset->rrtype == rrtype) {
                    return 1;
                }
            } else if (!skip_glue ||
                (rrset->rrtype != LDNS_RR_TYPE_A &&
                 rrset->rrtype != LDNS_RR_TYPE_AAAA)) {
                /* not glue or not skipping glue */
                return 1;
            }
        }
        node = ldns_rbtree_next(node);
    }
    return 0;
}


/**
 * Examine domain and verify if there is no other data next to a RRset.
 *
 */
int
domain_examine_rrset_is_alone(domain_type* domain, ldns_rr_type rrtype)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    ldns_dnssec_rrs* rrs = NULL;
    char* str_name = NULL;
    char* str_type = NULL;
    size_t count = 0;

    if (!domain || !rrtype) {
        return 1;
    }
    ods_log_assert(domain);
    ods_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset) {
        count = rrset_count_RR(rrset);
    }
    if (count) {
        if (domain_count_rrset(domain) < 2) {
            /* one or zero, that's ok */
            return 1;
        }
        /* make sure all other RRsets become empty */
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rrtype != rrtype && rrset_count_RR(rrset) > 0) {
                /* found other data next to rrtype */
                str_name = ldns_rdf2str(domain->dname);
                str_type = ldns_rr_type2str(rrtype);
                ods_log_error("[%s] other data next to %s %s", dname_str, str_name, str_type);
                rrs = rrset->rrs;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", LOG_ERR);
                    }
                    rrs = rrs->next;
                }
                rrs = rrset->add;
                while (rrs) {
                    if (rrs->rr) {
                        log_rr(rrs->rr, "next-to-CNAME: ", LOG_ERR);
                    }
                    rrs = rrs->next;
                }
                free((void*)str_name);
                free((void*)str_type);
                return 0;
            }
            node = ldns_rbtree_next(node);
        }
    }
    return 1;
}


/**
 * Examine domain and verify if there is no occluded data next to a delegation.
 *
 */
int
domain_examine_valid_zonecut(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain) {
        return 1;
    }
    ods_log_assert(domain);

    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset) {
        count = rrset_count_RR(rrset);
    }

    if (count) {
        /* make sure all other RRsets become empty (except DS, glue) */
        if (domain->rrsets->root != LDNS_RBTREE_NULL) {
            node = ldns_rbtree_first(domain->rrsets);
        }
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            if (rrset->rrtype != LDNS_RR_TYPE_DS &&
                rrset->rrtype != LDNS_RR_TYPE_NS &&
                rrset->rrtype != LDNS_RR_TYPE_A &&
                rrset->rrtype != LDNS_RR_TYPE_AAAA &&
                rrset_count_RR(rrset) > 0) {
                /* found occluded data next to delegation */
                ods_log_error("[%s] occluded glue data at zonecut, RRtype=%u",
                    dname_str, rrset->rrtype);
                return 0;
            } else if (rrset->rrtype == LDNS_RR_TYPE_A ||
                rrset->rrtype == LDNS_RR_TYPE_AAAA) {
                /* check if glue is allowed at the delegation */
/* TODO: allow for now (root zone has it)
                if (rrset_count_RR(rrset) > 0 &&
                    !domain_examine_ns_rdata(domain, domain->dname)) {
                    ods_log_error("[%s] occluded glue data at zonecut, #RR=%u",
                        dname_str, rrset_count_RR(rrset));
                    return 0;
                }
*/
            }
            node = ldns_rbtree_next(node);
        }
    }
    return 0;
}


/**
 * Examine domain and verify if the RRset is a singleton.
 *
 */
int
domain_examine_rrset_is_singleton(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* rrset = NULL;
    char* str_name = NULL;
    char* str_type = NULL;
    size_t count = 0;

    if (!domain || !rrtype) {
        return 1;
    }
    ods_log_assert(domain);
    ods_log_assert(rrtype);

    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset) {
        count = rrset_count_RR(rrset);
    }

    if (count > 1) {
        /* multiple RRs in the RRset for singleton RRtype*/
        str_name = ldns_rdf2str(domain->dname);
        str_type = ldns_rr_type2str(rrtype);
        ods_log_error("[%s] multiple records for singleton type at %s %s",
            dname_str, str_name, str_type);
        free((void*)str_name);
        free((void*)str_type);
        return 0;
    }
    return 1;
}


/**
 * Commit updates to domain.
 *
 */
ods_status
domain_commit(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    ods_status status = ODS_STATUS_OK;
    size_t numadd = 0;
    size_t numdel = 0;
    size_t numrrs = 0;
    size_t numnew = 0;

    if (!domain || !domain->rrsets) {
        return ODS_STATUS_OK;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    denial = (denial_type*) domain->denial;
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        numrrs = rrset_count_rr(rrset, COUNT_RR);
        numadd = rrset_count_rr(rrset, COUNT_ADD);
        numdel = rrset_count_rr(rrset, COUNT_DEL);

        if (rrset->rrtype == LDNS_RR_TYPE_SOA && rrset->rrs &&
            rrset->rrs->rr) {
            rrset->needs_signing = 1;
        }
        status = rrset_commit(rrset);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
        numnew = rrset_count_rr(rrset, COUNT_RR);
        if (numrrs > 0 && numnew <= 0) {
            if (domain_del_rrset(domain, rrset) != NULL) {
                ods_log_warning("[%s] unable to commit: failed ",
                    "to delete RRset", dname_str);
                return ODS_STATUS_UNCHANGED;
            }
            if (denial) {
                denial->bitmap_changed = 1;
            }
        } else if (numrrs <= 0 && numnew == numadd) {
            if (denial) {
                denial->bitmap_changed = 1;
            }
        }
    }
    return status;
}


/**
 * Rollback updates from domain.
 *
 */
void
domain_rollback(domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;

    if (!domain || !domain->rrsets) {
        return;
    }
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_rollback(rrset);
        node = ldns_rbtree_next(node);
    }
    return;
}


/**
 * Set domain status.
 *
 */
void
domain_dstatus(domain_type* domain)
{
    domain_type* parent = NULL;

    if (!domain) {
        ods_log_error("[%s] unable to set status: no domain", dname_str);
        return;
    }
    if (domain->dstatus == DOMAIN_STATUS_APEX) {
        /* that doesn't change... */
        return;
    }
    if (domain_count_rrset(domain) <= 0) {
        domain->dstatus = DOMAIN_STATUS_ENT;
        return;
    }

    if (domain_lookup_rrset(domain, LDNS_RR_TYPE_NS)) {
        if (domain_lookup_rrset(domain, LDNS_RR_TYPE_DS)) {
            domain->dstatus = DOMAIN_STATUS_DS;
        } else {
            domain->dstatus = DOMAIN_STATUS_NS;
        }
    } else {
        domain->dstatus = DOMAIN_STATUS_AUTH;
    }

    parent = domain->parent;
    while (parent && parent->dstatus != DOMAIN_STATUS_APEX) {
        if (domain_lookup_rrset(parent, LDNS_RR_TYPE_DNAME) ||
            domain_lookup_rrset(parent, LDNS_RR_TYPE_NS)) {
            domain->dstatus = DOMAIN_STATUS_OCCLUDED;
            return;
        }
        parent = parent->parent;
    }
    return;
}


/**
 * Queue all RRsets at this domain.
 *
 */
ods_status
domain_queue(domain_type* domain, fifoq_type* q, worker_type* worker)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    ods_status status = ODS_STATUS_OK;

    if (!domain || !domain->rrsets) {
        return ODS_STATUS_OK;
    }
    if (domain->dstatus == DOMAIN_STATUS_NONE ||
        domain->dstatus == DOMAIN_STATUS_OCCLUDED) {
        return ODS_STATUS_OK;
    }

    denial = (denial_type*) domain->denial;
    if (domain->rrsets->root != LDNS_RBTREE_NULL) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;

        /* skip delegation RRsets */
        if (domain->dstatus != DOMAIN_STATUS_APEX &&
            rrset->rrtype == LDNS_RR_TYPE_NS) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* skip glue at the delegation */
        if ((domain->dstatus == DOMAIN_STATUS_DS ||
             domain->dstatus == DOMAIN_STATUS_NS) &&
            (rrset->rrtype == LDNS_RR_TYPE_A ||
             rrset->rrtype == LDNS_RR_TYPE_AAAA)) {
            node = ldns_rbtree_next(node);
            continue;
        }
        /* queue RRset for signing */
        status = rrset_queue(rrset, q, worker);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        node = ldns_rbtree_next(node);
    }

    /* queue NSEC(3) RRset for signing */
    if (denial && denial->rrset) {
        status = rrset_queue(denial->rrset, q, worker);
    }
    return status;
}


/**
 * Examine domain NS RRset and verify its RDATA.
 *
 */
int
domain_examine_ns_rdata(domain_type* domain, ldns_rdf* nsdname)
{
    rrset_type* rrset = NULL;

    if (!domain || !nsdname) {
       return 0;
    }
    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset) {
        if (rrset_examine_ns_rdata(rrset, nsdname)) {
            return 1;
        }
    }
    return 0;
}


/**
 * Print domain.
 *
 */
void
domain_print(FILE* fd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    int print_glue = 0;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    rrset_type* cname_rrset = NULL;
    denial_type* denial = NULL;

    if (!domain || !fd) {
        return;
    }
    ods_log_assert(fd);
    ods_log_assert(domain);

    if (domain->rrsets) {
        node = ldns_rbtree_first(domain->rrsets);
    }
    /* no other data may accompany a CNAME */
    cname_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_CNAME);
    if (cname_rrset) {
        rrset_print(fd, cname_rrset, 0);
    } else {
        /* if SOA, print soa first */
        if (domain->dstatus == DOMAIN_STATUS_APEX) {
            soa_rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_SOA);
            if (soa_rrset) {
                rrset_print(fd, soa_rrset, 0);
            }
        }
        /* print other RRsets */
        while (node && node != LDNS_RBTREE_NULL) {
            rrset = (rrset_type*) node->data;
            /* skip SOA RRset */
            if (rrset->rrtype != LDNS_RR_TYPE_SOA) {
                if (domain->dstatus == DOMAIN_STATUS_OCCLUDED) {
                    /* glue?  */
                    print_glue = 1;
/* TODO: allow for now (root zone has it)
                    parent = domain->parent;
                    while (parent && parent->dstatus != DOMAIN_STATUS_APEX) {
                        if (domain_examine_ns_rdata(parent, domain->dname)) {
                            print_glue = 1;
                            break;
                        }
                        parent = parent->parent;
                    }
*/
                    if (print_glue && (rrset->rrtype == LDNS_RR_TYPE_A ||
                        rrset->rrtype == LDNS_RR_TYPE_AAAA)) {
                        rrset_print(fd, rrset, 0);
                    }
                } else {
                    rrset_print(fd, rrset, 0);
                }
            }
            node = ldns_rbtree_next(node);
        }
    }
    /* denial of existence */
    denial = (denial_type*) domain->denial;
    if (denial) {
        rrset_print(fd, denial->rrset, 0);
    }
    return;
}


/**
 * Clean up RRsets at the domain.
 *
 */
static void
rrset_delfunc(ldns_rbnode_t* elem)
{
    rrset_type* rrset;

    if (elem && elem != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) elem->data;
        rrset_delfunc(elem->left);
        rrset_delfunc(elem->right);

        rrset_cleanup(rrset);
        free(elem);
    }
    return;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    zone_type* zone = NULL;
    if (!domain) {
        return;
    }
    zone = (zone_type*) domain->zone;
    ldns_rdf_deep_free(domain->dname);
    if (domain->rrsets) {
        rrset_delfunc(domain->rrsets->root);
        ldns_rbtree_free(domain->rrsets);
        domain->rrsets = NULL;
    }
    allocator_deallocate(zone->allocator, (void*)domain);
    return;
}


/**
 * Backup domain.
 *
 */
void
domain_backup(FILE* fd, domain_type* domain)
{
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    char* str = NULL;
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;

    if (!domain || !fd) {
        return;
    }

    str = ldns_rdf2str(domain->dname);
    if (domain->rrsets) {
        node = ldns_rbtree_first(domain->rrsets);
    }

    fprintf(fd, ";;Domain: name %s status %i\n", str, (int) domain->dstatus);
    while (node && node != LDNS_RBTREE_NULL) {
        rrset = (rrset_type*) node->data;
        rrset_backup(fd, rrset);
        node = ldns_rbtree_next(node);
    }
    free((void*)str);

    /* denial of existence */
    denial = (denial_type*) domain->denial;
    if (denial) {
        fprintf(fd, ";;Denial\n");
        rrset_print(fd, denial->rrset, 1);
        rrset_backup(fd, denial->rrset);
    }

    fprintf(fd, ";;Domaindone\n");
    return;
}
