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
#include "signer/rrset.h"

#include <ldns/ldns.h>
#include <time.h>

#define DOMAIN_STATUS_NONE      0
#define DOMAIN_STATUS_APEX      1
#define DOMAIN_STATUS_AUTH      2
#define DOMAIN_STATUS_NS        3
#define DOMAIN_STATUS_ENT_AUTH  4
#define DOMAIN_STATUS_ENT_NS    5
#define DOMAIN_STATUS_ENT_GLUE  6
#define DOMAIN_STATUS_OCCLUDED  7
#define DOMAIN_STATUS_HASH      8

/**
 * Domain.
 *
 */
typedef struct domain_struct domain_type;
struct domain_struct {
    ldns_rdf* name;
    domain_type* parent;
    domain_type* nsec3;
    ldns_rr_list* rrs_add;
    ldns_rr_list* rrs_del;
    ldns_rbtree_t* rrsets;
    int domain_status;
    uint32_t inbound_serial;
    uint32_t outbound_serial;
};

/**
 * Create empty domain.
 * \param[in] dname owner name
 * \return domain_type* empty domain
 *
 */
domain_type* domain_create(ldns_rdf* dname);


/**
 * Lookup a RRset within the domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \return rrset_type* RRset if found
 *
 */
rrset_type* domain_lookup_rrset(domain_type* domain, rrset_type* rrset);


/**
 * Add a RRset to the domain.
 * \param[in] domain domain
 * \param[in] rrset RRset
 * \return rrset_type* added RRset
 *
 */
rrset_type* domain_add_rrset(domain_type* domain, rrset_type* rrset);


/**
 * Commit the added and deleted RRs.
 * \param[in] domain domain
 * \param[in] serial version to migrate to
 * \return int 0 on success, 1 on error
 *
 */
int domain_commit_changes(domain_type* domain, uint32_t serial);

/**
 * Add RR to the list of RRs to add to this domain.
 * \param[in] domain domain
 * \param[in] rr RR
 * \param[in] serial version of zone this RR was added
 * \return int 0 on success, 1 on error
 *
 */
int domain_add_rr(domain_type* domain, ldns_rr* rr, uint32_t serial);

/**
 * Add RR to the list of RRs to delete from this domain.
 * \param[in] domain domain
 * \param[in] rr RR
 * \param[in] serial version of zone this RR was deleted
 * \return int 0 on success, 1 on error
 *
 */
int domain_del_rr(domain_type* domain, ldns_rr* rr, uint32_t serial);

/**
 * Clean up domain.
 * \param[in] domain domain to cleanup
 *
 */
void domain_cleanup(domain_type* domain);

#endif /* SIGNER_DOMAIN_H */
