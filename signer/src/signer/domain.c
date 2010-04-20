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
#include "signer/domain.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h>


/**
 * Create empty domain.
 *
 */
domain_type*
domain_create(ldns_rdf* dname)
{
    domain_type* domain = (domain_type*) se_malloc(sizeof(domain_type));
    se_log_assert(dname);

    domain->name = ldns_rdf_clone(dname);
    domain->parent = NULL;
    domain->nsec3 = NULL;
    domain->domain_status = DOMAIN_STATUS_NONE;
    return domain;
}


/**
 * Clean up domain.
 *
 */
void
domain_cleanup(domain_type* domain)
{
    if (domain) {
        if (domain->name) {
            ldns_rdf_deep_free(domain->name);
            domain->name = NULL;
        }
        /* don't destroy corresponding parent and nsec3 domain */
        se_free((void*) domain);
    } else {
        se_log_warning("cleanup empty domain");
    }
}
