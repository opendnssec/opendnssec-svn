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

#ifndef SIGNER_DOMAIN_H
#define SIGNER_DOMAIN_H

#include "config.h"
#include "daemon/worker.h"
#include "scheduler/fifoq.h"
#include "shared/allocator.h"
#include "shared/status.h"
#include "signer/denial.h"
#include "signer/keys.h"
#include "signer/rrset.h"

#include <ldns/ldns.h>
#include <time.h>

#define SE_NSEC_RDATA_NXT          0
#define SE_NSEC_RDATA_BITMAP       1
#define SE_NSEC3_RDATA_NSEC3PARAMS 4
#define SE_NSEC3_RDATA_NXT         4
#define SE_NSEC3_RDATA_BITMAP      5

enum domain_status_enum {
    DOMAIN_STATUS_NONE = 0, /* initial domain status [UNSIGNED] */
    DOMAIN_STATUS_APEX,     /* apex domain, authoritative [SIGNED] */
    DOMAIN_STATUS_AUTH,     /* authoritative domain, non-apex [SIGNED] */
    DOMAIN_STATUS_NS,       /* unsigned delegation [UNSIGNED] */
    DOMAIN_STATUS_DS,       /* signed delegation [SIGNED] */
    DOMAIN_STATUS_ENT,      /* empty non-terminal [UNSIGNED] */
    DOMAIN_STATUS_OCCLUDED  /* occluded domain [UNSIGNED] */
};
typedef enum domain_status_enum domain_status;

/**
 * Domain.
 *
 */
typedef struct domain_struct domain_type;
struct domain_struct {
    void* zone;
    void* denial;
    ldns_rbnode_t* node;
    ldns_rdf* dname;
    domain_type* parent;
    rrset_type* rrsets;
    unsigned is_new : 1;
    unsigned is_apex : 1; /* apex */
};

/**
 * Log domain name.
 * \param[in] rdf domain name
 * \param[in] pre log message
 * \param[in] level log level
 *
 */
void log_dname(ldns_rdf* rdf, const char* pre, int level);

/**
 * Create domain.
 * \param[in] zoneptr zone reference
 * \param[in] dname owner name
 * \return domain_type* domain
 *
 */
domain_type* domain_create(void* zoneptr, ldns_rdf* dname);

/**
 * Recover domain from backup.
 * \param[in] domain domain
 * \param[in] fd backup file descriptor
 * \param[in] dstatus domain status
 * \return ods_status status
 *
 */
ods_status domain_recover(domain_type* domain, FILE* fd,
    domain_status dstatus);

/**
 * Recover RR from backup.
 * \param[in] domain domain
 * \param[in] rr RR
 * \return int 0 on success, 1 on error
 *
 */
/*
int domain_recover_rr_from_backup(domain_type* domain, ldns_rr* rr);
*/

/**
 * Recover RRSIG from backup.
 * \param[in] domain domain
 * \param[in] rrsig RRSIG
 * \param[in] type_covered RRtype that is covered by rrsig
 * \param[in] locator key locator
 * \param[in] flags key flags
 * \return int 0 on success, 1 on error
 *
 */
/*
int domain_recover_rrsig_from_backup(domain_type* domain, ldns_rr* rrsig,
    ldns_rr_type type_covered, const char* locator, uint32_t flags);
*/

/**
 * Count the number of RRsets at this domain.
 * \param[in] domain domain
 * \return size_t number of RRsets
 *
 */
size_t domain_count_rrset(domain_type* domain);

/**
 * Look up RRset at this domain.
 * \param[in] domain the domain
 * \param[in] rrtype RRtype
 * \return rrset_type* RRset, if found
 *
 */
rrset_type* domain_lookup_rrset(domain_type* domain, ldns_rr_type rrtype);

/**
 * Add RRset to domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \return rrset_type* added RRset
 *
 */
rrset_type* domain_add_rrset(domain_type* domain, rrset_type* rrset);

/**
 * Delete RRset from domain.
 * \param[in] domain domain
 * \param[in] rrtype RRtype of RRset
 * \return rrset_type* deleted RRset
 *
 */
rrset_type* domain_del_rrset(domain_type* domain, ldns_rr_type rrtype);

/**
 * Apply differences at domain.
 * \param[in] domain domain
 *
 */
void domain_diff(domain_type* domain);

/**
 * Examine domain and verify if data exists.
 * \param[in] domain domain
 * \param[in] rrtype RRtype look for a specific RRset
 * \param[in] skip_glue skip glue records
 * \retun int 0 if data is alone, 1 otherwise
 *
 */
int domain_examine_data_exists(domain_type* domain, ldns_rr_type rrtype,
    int skip_glue);

/**
 * Examine domain NS RRset and verify its RDATA.
 * \param[in] domain domain
 * \param[in] nsdname domain name that should match one of the NS RDATA
 * \return int 1 if match, 0 otherwise
 *
 */
int domain_examine_ns_rdata(domain_type* domain, ldns_rdf* nsdname);

/**
 * Examine domain and verify if it is a valid zonecut (or no NS RRs).
 * \param[in] domain domain
 * \retun int 1 if the RRset is a valid zonecut (or no zonecut), 0 otherwise
 *
 */
int domain_examine_valid_zonecut(domain_type* domain);

/**
 * Examine domain and verify if there is no other data next to a RRset.
 * \param[in] domain domain
 * \param[in] rrtype RRtype
 * \return int 1 if the RRset is alone, 0 otherwise
 *
 */
int domain_examine_rrset_is_alone(domain_type* domain, ldns_rr_type rrtype);

/**
 * Examine domain and verify if the RRset is a singleton.
 * \param[in] domain domain
 * \param[in] rrtype RRtype
 * \return int 1 if the RRset is a singleton, 0 otherwise
 *
 */
int domain_examine_rrset_is_singleton(domain_type* domain, ldns_rr_type rrtype);

/**
 * Rollback updates from domain.
 * \param[in] domain the domain
 *
 */
void domain_rollback(domain_type* domain);

/**
 * Check whether a domain is an empty non-terminal to an unsigned delegation.
 * \param[in] domain domain
 * \return int yes or no
 *
 */
int domain_ent2unsignedns(domain_type* domain);

/**
 * Check whether a domain is a delegation, regardless of parent.
 * \param[in] domain domain
 * \return ldns_rr_type RRtype that hints whether the domain is occluded.
 *         LDNS_RR_TYPE_NS Unsigned delegation
 *         LDNS_RR_TYPE_DS Signed delegation
 *         LDNS_RR_TYPE_SOA Authoritative data (or signed delegation)
 *
 */
ldns_rr_type domain_is_delegpt(domain_type* domain);

/**
 * Check whether the domain is occluded.
 * \param[in] domain domain
 * \return ldns_rr_type RRtype that hints whether the domain is occluded.
 *         LDNS_RR_TYPE_DNAME Occluded
 *         LDNS_RR_TYPE_A Glue
 *         LDNS_RR_TYPE_SOA Authoritative data or delegation
 *
 */
ldns_rr_type domain_is_occluded(domain_type* domain);

/**
 * Queue all RRsets at this domain.
 * \param[in] domain the domain
 * \param[in] q queue
 * \param[in] worker owner of data
 * \return ods_status status
 *
 */
ods_status domain_queue(domain_type* domain, fifoq_type* q,
    worker_type* worker);

/**
 * Print domain.
 * \param[in] fd file descriptor
 * \param[in] domain domain
 *
 */
void domain_print(FILE* fd, domain_type* domain);

/**
 * Clean up domain.
 * \param[in] domain domain to cleanup
 *
 */
void domain_cleanup(domain_type* domain);

/**
 * Backup domain.
 * \param[in] fd file descriptor
 * \param[in] domain domain
 *
 */
void domain_backup(FILE* fd, domain_type* domain);

#endif /* SIGNER_DOMAIN_H */
