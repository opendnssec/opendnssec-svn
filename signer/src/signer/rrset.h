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
 * RRset.
 *
 */

#ifndef SIGNER_RRSET_H
#define SIGNER_RRSET_H

#include "config.h"
#include "signer/signconf.h"

#include <ldns/ldns.h>

typedef struct rrset_struct rrset_type;
struct rrset_struct {
    ldns_rr_type rr_type;
    ldns_dnssec_rrs* rrs;
    ldns_dnssec_rrs* rrsigs;
    rrset_type* next;
};

/**
 * Create new RRset.
 * \param[in] rr first RR in the new RRset
 * \return new RRset
 *
 */
rrset_type* rrset_create(ldns_rr* rr);

/**
 * Clean up RRset.
 * \param[in] rrset RRset to be cleaned up
 *
 */
void rrset_cleanup(rrset_type* rrset);

/**
 * Look if the RRset covers a RRtype.
 * \param[in] rrset RRset to be checked
 * \param[in] rr_type RRtype
 * \return 1 if true, 0 if false
 *
 */
int rrset_covers_rrtype(rrset_type* rrset, ldns_rr_type rr_type);

/**
 * Print RRset.
 * \param[in] fd file descriptor
 * \param[in] rrset RRset to be printed
 * \param[in] comments print additional comments
 * \param[in] follow also print following RRsets
 * \param[in] glue_only only print A/AAAA RRs
 * \param[in] skip_soa skip SOA record, because it was printed seperately
 *
 */
void rrset_print(FILE* fd, rrset_type* rrset, const char* comments, int follow,
    int glue_only, int skip_soa);

#endif /* SIGNER_RRSET_H */
