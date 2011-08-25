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
    domain->rrsets = NULL;
    domain->parent = NULL;
    domain->dstatus = DOMAIN_STATUS_NONE;
    return domain;
}


/**
 * Count the number of RRsets at this domain.
 *
 */
size_t
domain_count_rrset(domain_type* domain)
{
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain) {
        return 0;
    }
    rrset = domain->rrsets;
    while (rrset) {
        count++; /* rr_count may be zero */
        rrset = rrset->next;
    }
    return count;
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
            rrset_diff(denial->rrset);
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
 * Look up RRset at this domain.
 *
 */
rrset_type*
domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* rrset = NULL;
    if (!domain || !domain->rrsets || !rrtype) {
        return NULL;
    }
    rrset = domain->rrsets;
    while (rrset && rrset->rrtype != rrtype) {
        rrset = rrset->next;
    }
    return rrset;
}


/**
 * Add RRset to domain.
 *
 */
rrset_type*
domain_add_rrset(domain_type* domain, rrset_type* rrset)
{
    rrset_type** p = NULL;
    denial_type* denial = NULL;
    ods_log_assert(domain);
    ods_log_assert(rrset);
    if (!domain->rrsets) {
        domain->rrsets = rrset;
    } else {
        p = &domain->rrsets;
        while(*p) {
            p = &((*p)->next);
        }
        *p = rrset;
        rrset->next = NULL;
    }
    log_rrset(domain->dname, rrset->rrtype, "+RRSET", LOG_DEBUG);
    if (domain->denial) {
        denial = (denial_type*) domain->denial;
        denial->bitmap_changed = 1;
    }
    return rrset;
}


/**
 * Delete RRset from domain.
 *
 */
rrset_type*
domain_del_rrset(domain_type* domain, ldns_rr_type rrtype)
{
    rrset_type* cur = NULL;
    denial_type* denial = NULL;
    if (!domain || !rrtype) {
        return NULL;
    }
    if (!domain->rrsets) {
        ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
            "does not exist", dname_str, rrset_type2str(rrtype));
        return NULL;
    }
    if (domain->rrsets->rrtype == rrtype) {
        cur = domain->rrsets;
        domain->rrsets = cur->next;
        cur->domain = NULL;
        cur->next = NULL;
        log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEBUG);
        if (domain->denial) {
            denial = (denial_type*) domain->denial;
            denial->bitmap_changed = 1;
        }
        return cur;
    }
    cur = domain->rrsets;
    while (cur) {
        if (!cur->next) {
            ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
                "does not exist", dname_str, rrset_type2str(rrtype));
            return NULL;
        }
        ods_log_assert(cur->next);
        if (cur->next->rrtype != rrtype) {
            cur = cur->next;
        } else {
            ods_log_assert(cur->next->rrtype == rrtype);
            cur->next = cur->next->next;
            cur = cur->next;
            cur->domain = NULL;
            cur->next = NULL;
            log_rrset(domain->dname, rrtype, "-RRSET", LOG_DEBUG);
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 1;
            }
            return cur;
        }
    }
    ods_log_error("[%s] unable to delete RRset: RRset with RRtype %s "
        "does not exist", dname_str, rrset_type2str(rrtype));
    return NULL;
}


/**
 * Apply differences at domain.
 *
 */
void
domain_diff(domain_type* domain)
{
    denial_type* denial = NULL;
    rrset_type* rrset = NULL;
    rrset_type* prev_rrset = NULL;

    if (!domain) {
        return;
    }
    rrset = domain->rrsets;
    while (rrset) {
        /* special cases */
        if (rrset->rrtype == LDNS_RR_TYPE_NSEC3PARAMS) {
            rrset = rrset->next;
            continue;
        }
        /* normal cases */
        rrset_diff(rrset);
        if (rrset->rr_count <= 0) {
            /* delete entire rrset */
            if (!prev_rrset) {
                domain->rrsets = rrset->next;
            } else {
                prev_rrset->next = rrset->next;
            }
            rrset->next = NULL;
            log_rrset(domain->dname, rrset->rrtype, "-RRSET", LOG_DEBUG);
            rrset_cleanup(rrset);
            if (!prev_rrset) {
                rrset = domain->rrsets;
            } else {
                rrset = prev_rrset->next;
            }
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 1;
            }
        } else {
            /* just go to next rrset */
            prev_rrset = rrset;
            rrset = rrset->next;
        }
    }
    return;
}


/**
 * Rollback differences at domain.
 *
 */
void
domain_rollback(domain_type* domain)
{
    denial_type* denial = NULL;
    rrset_type* rrset = NULL;
    rrset_type* prev_rrset = NULL;
    ldns_rr* del_rr = NULL;
    int del_rrset = 0;
    uint16_t i = 0;

    if (!domain) {
        return;
    }
    rrset = domain->rrsets;
    while (rrset) {
        /* walk rrs */
        for (i=0; i < rrset->rr_count; i++) {
            rrset->rrs[i].is_added = 0;
            rrset->rrs[i].is_removed = 0;
            if (!rrset->rrs[i].exists) {
                /* can we delete the RRset? */
                if(rrset->rr_count == 1) {
                    del_rrset = 1;
                }
                del_rr = rrset->rrs[i].rr;
                rrset_del_rr(rrset, i);
                ldns_rr_free(del_rr);
                del_rr = NULL;
                i--;
            }
        }
        /* next rrset */
        if (del_rrset) {
            /* delete entire rrset */
            if (!prev_rrset) {
                domain->rrsets = rrset->next;
            } else {
                prev_rrset->next = rrset->next;
            }
            rrset->next = NULL;
            log_rrset(domain->dname, rrset->rrtype, "-RRSET", LOG_DEBUG);
            rrset_cleanup(rrset);
            if (!prev_rrset) {
                rrset = domain->rrsets;
            } else {
                rrset = prev_rrset->next;
            }
            if (domain->denial) {
                denial = (denial_type*) domain->denial;
                denial->bitmap_changed = 0;
            }
            del_rrset = 0;
        } else {
            /* just go to next rrset */
            prev_rrset = rrset;
            rrset = rrset->next;
        }
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
    rrset_type* rrset = NULL;
    uint16_t i = 0;

    if (!domain) {
        return 0;
    }
    rrset = domain->rrsets;
    while (rrset) {
        /* walk rrs */
        for (i=0; i < rrset->rr_count; i++) {
            if (!rrset->rrs[i].exists) {
                rrset = rrset->next;
                continue;
            }
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
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain || !rrtype) {
        return 1;
    }
    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset) {
        count = rrset->rr_count;
    }
    if (count) {
        if (domain_count_rrset(domain) < 2) {
            /* one or zero, that's ok */
            return 1;
        }
        rrset = domain->rrsets;
        while (rrset) {
            if (rrset->rrtype != rrtype && rrset->rr_count > 0) {
                /* found other data next to rrtype */
                log_dname(domain->dname, "other data next to RRset", LOG_ERR);
                return 0;
            }
            rrset = rrset->next;;
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
    rrset_type* rrset = NULL;
    size_t count = 0;

    if (!domain) {
        return 1;
    }
    rrset = domain_lookup_rrset(domain, LDNS_RR_TYPE_NS);
    if (rrset) {
        count = rrset->rr_count;
    }
    if (count) {
        /* make sure all other RRsets become empty (except DS, glue) */
        rrset = domain->rrsets;
        while (rrset) {
            if (rrset->rrtype != LDNS_RR_TYPE_DS &&
                rrset->rrtype != LDNS_RR_TYPE_NS &&
                rrset->rrtype != LDNS_RR_TYPE_A &&
                rrset->rrtype != LDNS_RR_TYPE_AAAA &&
                rrset->rr_count > 0) {
                /* found occluded data next to delegation */
                ods_log_error("[%s] occluded glue data at zonecut, RRtype=%u",
                    dname_str, rrset->rrtype);
                return 0;
            } else if (rrset->rrtype == LDNS_RR_TYPE_A ||
                rrset->rrtype == LDNS_RR_TYPE_AAAA) {
                /* check if glue is allowed at the delegation */
/* TODO: allow for now (root zone has it)
                if (rrset->rr_count > 0 &&
                    !domain_examine_ns_rdata(domain, domain->dname)) {
                    ods_log_error("[%s] occluded glue data at zonecut, #RR=%u",
                        dname_str, rrset->rr_count);
                    return 0;
                }
*/
            }
            rrset = rrset->next;
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
    size_t count = 0;

    if (!domain || !rrtype) {
        return 1;
    }
    rrset = domain_lookup_rrset(domain, rrtype);
    if (rrset) {
        count = rrset->rr_count;
    }
    if (count > 1) {
        /* multiple RRs in the RRset for singleton RRtype*/
        log_dname(domain->dname, "multiple records for singleton type",
            LOG_ERR);
        return 0;
    }
    return 1;
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
    rrset = domain->rrsets;
    while (rrset) {
        /* skip delegation RRsets */
        if (domain->dstatus != DOMAIN_STATUS_APEX &&
            rrset->rrtype == LDNS_RR_TYPE_NS) {
            rrset = rrset->next;
            continue;
        }
        /* skip glue at the delegation */
        if ((domain->dstatus == DOMAIN_STATUS_DS ||
             domain->dstatus == DOMAIN_STATUS_NS) &&
            (rrset->rrtype == LDNS_RR_TYPE_A ||
             rrset->rrtype == LDNS_RR_TYPE_AAAA)) {
            rrset = rrset->next;
            continue;
        }
        /* queue RRset for signing */
        status = rrset_queue(rrset, q, worker);
        if (status != ODS_STATUS_OK) {
            return status;
        }
        rrset = rrset->next;
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
    int print_glue = 0;
    rrset_type* rrset = NULL;
    rrset_type* soa_rrset = NULL;
    rrset_type* cname_rrset = NULL;
    denial_type* denial = NULL;

    if (!domain || !fd) {
        return;
    }
    rrset = domain->rrsets;
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
        while (rrset) {
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
            rrset = rrset->next;
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
    rrset_cleanup(domain->rrsets);
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
    char* str = NULL;
    rrset_type* rrset = NULL;
    denial_type* denial = NULL;
    if (!domain || !fd) {
        return;
    }
    str = ldns_rdf2str(domain->dname);
    fprintf(fd, ";;Domain: name %s status %i\n", str, (int) domain->dstatus);
    rrset = domain->rrsets;
    while (rrset) {
        rrset_backup(fd, rrset);
        rrset = rrset->next;;
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
