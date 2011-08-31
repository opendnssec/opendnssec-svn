/*
 * $Id: namedb.h 5465 2011-08-23 14:39:28Z matthijs $
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

#ifndef SIGNER_NAMEDB_H
#define SIGNER_NAMEDB_H

#include "config.h"
#include "adapter/adapter.h"
#include "shared/allocator.h"
#include "shared/status.h"
#include "signer/denial.h"
#include "signer/domain.h"
#include "signer/keys.h"
#include "signer/signconf.h"
#include "signer/stats.h"
#include "signer/nsec3params.h"

#include <ldns/ldns.h>
#include <stdio.h>

/**
 * Domain name database.
 *
 */
typedef struct namedb_struct namedb_type;
struct namedb_struct {
    void* zone;
    ldns_rbtree_t* domains;
    ldns_rbtree_t* denials;
    uint32_t inbserial;
    uint32_t intserial;
    uint32_t outserial;
    unsigned is_initialized : 1;
    unsigned is_processed : 1;
    unsigned serial_updated : 1;
};

/**
 * Initialize denial of existence chain.
 * \param[in] db namedb
 *
 */
void namedb_init_denials(namedb_type* db);

/**
 * Create a new namedb.
 * \param[in] zone zone reference
 * \return namedb_type* namedb
 *
 */
namedb_type* namedb_create(void* zone);

/**
 * Determine new SOA SERIAL.
 * \param[in] db namedb
 * \param[in] format <SOA><Serial> format from signer configuration
 * \param[in] serial inbound serial
 * \return ods_status status
 *
 */
ods_status namedb_update_serial(namedb_type* db, const char* format,
    uint32_t serial);

/**
 * Add empty non-terminals for domain.
 * \param[in] db namedb
 * \param[in] domain domain
 * \param[in] apex apex domain name
 * \return ods_status status
 *
 */
ods_status namedb_domain_entize(namedb_type* db, domain_type* domain,
 ldns_rdf* apex);

/**
 * Look up domain.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \return domain_type* domain, if found
 *
 */
domain_type* namedb_lookup_domain(namedb_type* db, ldns_rdf* dname);

/**
 * Add domain to namedb.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \return domain_type* added domain
 *
 */
domain_type* namedb_add_domain(namedb_type* db, ldns_rdf* dname);

/**
 * Delete domain from namedb
 * \param[in] db namedb
 * \param[in] domain domain
 * \return domain_type* deleted domain
 *
 */
domain_type* namedb_del_domain(namedb_type* db, domain_type* domain);

/**
 * Lookup denial.
 * \param[in] db namedb
 * \param[in] dname domain name
 * \return denial_type* denial, if found
 *
 */
denial_type* namedb_lookup_denial(namedb_type* db, ldns_rdf* dname);

/**
 * Add denial to namedb.
 * \param[in] db namedb
 * \param[in] domain corresponding domain
 * \param[in] apex apex
 * \param[in] n3p NSEC3 parameters, NULL if we do NSEC
 * \return ods_status status
 *
 */
ods_status namedb_add_denial(namedb_type* db, domain_type* domain,
    ldns_rdf* apex, nsec3params_type* n3p);

/**
 * Delete denial from namedb
 * \param[in] db namedb
 * \param[in] denial denial
 * \return denial_type* deleted denial
 *
 */
denial_type* namedb_del_denial(namedb_type* db, denial_type* denial);

/**
 * Examine updates to zone data.
 * \param[in] zd zone data
 * \param[in] apex apex domain name
 * \param[in] mode adapter mode
 * \return ods_status status
 *
 */
ods_status namedb_examine(namedb_type* zd, ldns_rdf* apex,
    adapter_mode mode);

/**
 * Apply differences in db.
 * \param[in] db namedb
 *
 */
void namedb_diff(namedb_type* db);

/**
 * Rollback differences in db.
 * \param[in] db namedb
 *
 */
void namedb_rollback(namedb_type* db);

/**
 * Nsecify db.
 * \param[in] db namedb
 * \param[in] klass zone class
 * \param[in] ttl NSEC ttl
 * \param[out] num_added number of NSEC RRs added
 * \return ods_status status
 *
 */
ods_status namedb_nsecify(namedb_type* db, ldns_rr_class klass,
    uint32_t ttl, uint32_t* num_added);

/**
 * Nsecify3 db.
 * \param[in] db namedb
 * \param[in] klass zone class
 * \param[in] ttl NSEC3 ttl
 * \param[in] nsec3params NSEC3 parameters
 * \param[out] num_added number of NSEC3 RRs added
 * \return ods_status status
 *
 */
ods_status namedb_nsecify3(namedb_type* db, ldns_rr_class klass,
    uint32_t ttl, nsec3params_type* nsec3params, uint32_t* num_added);

/**
 * Export db to file.
 * \param[in] fd file descriptor
 * \param[in] namedb namedb
 *
 */
void namedb_export(FILE* fd, namedb_type* db);

/**
 * Wipe out all NSEC(3) RRsets.
 * \param[in] zd zone data
 *
 */
void namedb_wipe_denial(namedb_type* zd);

/**
 * Clean up denial of existence chain.
 * \param[in] zd zone data
 *
 */
void namedb_cleanup_chain(namedb_type* zd);

/**
 * Clean up namedb.
 * \param[in] namedb namedb
 *
 */
void namedb_cleanup(namedb_type* db);


/**
 * Backup zone data.
 * \param[in] fd output file descriptor
 * \param[in] zd zone data
 *
 */
void namedb_backup(FILE* fd, namedb_type* zd);

/**
 * Recover zone data from backup.
 * \param[in] zd zone data
 * \param[in] fd backup file descriptor
 * \return ods_status status
 *
 */
ods_status namedb_recover(namedb_type* zd, FILE* fd);

#endif /* SIGNER_NAMEDB_H */
