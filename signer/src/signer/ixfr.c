/*
 * $Id: ixfr.c 5260 2011-06-28 14:13:14Z matthijs $
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
 * IXFR Journal.
 *
 */

#include "config.h"
#include "signer/ixfr.h"
#include "signer/rrset.h"
#include "signer/zone.h"

static const char* ixfr_str = "journal";


/**
 * Create a new ixfr journal.
 *
 */
ixfr_type*
ixfr_create(void* zone)
{
    ixfr_type* xfr = NULL;
    zone_type* z = (zone_type*) zone;

    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->allocator);

    xfr = (ixfr_type*) allocator_alloc(z->allocator, sizeof(ixfr_type));
    if (!xfr) {
        ods_log_error("[%s] unable to create ixfr for zone %s: "
            "allocator_alloc() failed", ixfr_str, z->name);
        return NULL;
    }
    xfr->plus = ldns_rr_list_new();
    if (!xfr->plus) {
        ods_log_error("[%s] unable to create ixfr for zone %s: "
            "ldns_rr_list_new() failed", ixfr_str, z->name);
        allocator_deallocate(z->allocator, (void*) xfr);
        return NULL;
    }
    xfr->min = ldns_rr_list_new();
    if (!xfr->min) {
        ods_log_error("[%s] unable to create ixfr for zone %s: "
            "ldns_rr_list_new() failed", ixfr_str, z->name);
        ldns_rr_list_free(xfr->plus);
        allocator_deallocate(z->allocator, (void*) xfr);
        return NULL;
    }
    xfr->zone = zone;
    return xfr;
}


/**
 * Add +RR to ixfr journal.
 *
 */
void
ixfr_add_rr(ixfr_type* ixfr, ldns_rr* rr)
{
    if (!ixfr || !rr) {
        return;
    }
    ods_log_assert(ixfr->plus);
    if (!ldns_rr_list_push_rr(ixfr->plus, rr)) {
        ods_log_error("[%s] unable to +RR: ldns_rr_list_pus_rr() failed",
            ixfr_str);
        exit(1);
    }
    return;
}


/**
 * Add -RR to ixfr journal.
 *
 */
void
ixfr_del_rr(ixfr_type* ixfr, ldns_rr* rr)
{
    if (!ixfr || !rr) {
        return;
    }
    ods_log_assert(ixfr->min);
    if (!ldns_rr_list_push_rr(ixfr->min, rr)) {
        ods_log_error("[%s] unable to +RR: ldns_rr_list_pus_rr() failed",
            ixfr_str);
        exit(1);
    }
    return;
}


/**
 * Print the ixfr journal.
 *
 */
void
ixfr_print(FILE* fd, ixfr_type* ixfr)
{
    if (!ixfr || !fd) {
        return;
    }
    ods_log_assert(ixfr->plus);
    ods_log_assert(ixfr->min);
    fprintf(fd, ";; -RR\n");
    ldns_rr_list_print(fd, ixfr->min);
    fprintf(fd, ";; +RR\n");
    ldns_rr_list_print(fd, ixfr->plus);
    fprintf(fd, "\n");
    return;
}


/**
 * Wipe the ixfr journal.
 *
 */
void
ixfr_wipe(ixfr_type* ixfr)
{
    if (!ixfr) {
        return;
    }
    ods_log_assert(ixfr->plus);
    ods_log_assert(ixfr->min);

    ldns_rr_list_deep_free(ixfr->min);
    ldns_rr_list_free(ixfr->plus);

    ixfr->min = ldns_rr_list_new();
    ixfr->plus = ldns_rr_list_new();
    if (!ixfr->min || !ixfr->plus) {
        ods_log_error("[%s] unable to wipe ixfr: ldns_rr_list_new() failed",
            ixfr_str);
        exit(1);
    }
    return;
}


/**
 * Cleanup the ixfr journal.
 *
 */
void
ixfr_cleanup(ixfr_type* ixfr)
{
    zone_type* z = NULL;
    if (!ixfr) {
        return;
    }
    ods_log_assert(ixfr->plus);
    ods_log_assert(ixfr->min);
    ldns_rr_list_deep_free(ixfr->min);
    ldns_rr_list_free(ixfr->plus);
    z = (zone_type*) ixfr->zone;
    allocator_deallocate(z->allocator, (void*) ixfr);
    return;
}
