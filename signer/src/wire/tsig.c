/*
 * $Id: tsig.c 4958 2011-04-18 07:11:09Z matthijs $
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * TSIG.
 *
 */

#include "config.h"
#include "compat.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "wire/tsig.h"

static const char* tsig_str = "tsig";
/** allocator */
static allocator_type* tsig_allocator = NULL;
/** key table */
/*
typedef struct tsig_key_table_struct tsig_key_table_type;
struct tsig_key_table_struct {
        tsig_key_table_type* next;
        tsig_key_type* key;
};
static tsig_key_table_type* tsig_key_table = NULL;
*/
/** algorithm table */
/*
typedef struct tsig_algo_table_struct tsig_algo_table_type;
struct tsig_algo_table_struct {
    tsig_algo_table_type* next;
    tsig_algo_type* algorithm;
};
*/
/*
static tsig_algo_table_type* tsig_algo_table = NULL;
*/
/** maximum algorithm digest size */
static size_t max_algo_digest_size = 0;
/** lookup algorithm table */
/*
tsig_lookup_algorithm_table tsig_supported_algorithms[] = {
        { TSIG_HMAC_MD5, "hmac-md5" },
#ifdef HAVE_EVP_SHA1
        { TSIG_HMAC_SHA1, "hmac-sha1" },
#endif
#ifdef HAVE_EVP_SHA256
        { TSIG_HMAC_SHA256, "hmac-sha256" },
#endif
        { 0, NULL }
};
*/

/**
 * Initialize TSIG handler.
 *
 */
ods_status
tsig_handler_init(allocator_type* allocator)
{
    if (!allocator) {
        return ODS_STATUS_ERR;
    }
    tsig_allocator = allocator;
/*
    tsig_key_table = NULL;
    tsig_algo_table = NULL;
*/
    /* SSL */
    return ODS_STATUS_OK;
}


/**
 * Create new TSIG key.
 *
 */
tsig_key_type*
tsig_key_create(allocator_type* allocator, tsig_type* tsig)
{
    tsig_key_type* key = NULL;
    ldns_rdf* dname = NULL;
    uint8_t* data = NULL;
    int size = 0;
    if (!allocator || !tsig || !tsig->name || !tsig->secret) {
        return NULL;
    }
    key = (tsig_key_type*) allocator_alloc(allocator, sizeof(tsig_key_type));
    if (!key) {
        return NULL;
    }
    dname = ldns_dname_new_frm_str(tsig->name);
    if (!dname) {
        return NULL;
    }
    data = allocator_alloc(allocator, sizeof(uint8_t) *
        util_b64_pton_calculate_size(strlen(tsig->secret)));
    if (!data) {
        ldns_rdf_deep_free(dname);
        return NULL;
    }
    size = b64_pton(tsig->secret, data,
        util_b64_pton_calculate_size(strlen(tsig->secret)));
    if (size < 0) {
        ods_log_error("[%s] unable to create tsig key %s: failed to parse "
            "secret", tsig_str, tsig->name);
        ldns_rdf_deep_free(dname);
        allocator_deallocate(allocator, (void*)data);
    }
    key->dname = dname;
    key->size = size;
    key->data = data;
    /* tsig add key */
    return key;
}


/**
 * Create new TSIG.
 *
 */
tsig_type*
tsig_create(allocator_type* allocator, char* name, char* algo, char* secret)
{
    tsig_type* tsig = NULL;
    if (!allocator || !name || !algo || !secret) {
        return NULL;
    }
    tsig = (tsig_type*) allocator_alloc(allocator, sizeof(tsig_type));
    if (!tsig) {
        ods_log_error("[%s] unable to create tsig: allocator_alloc() "
            "failed", tsig_str);
        return NULL;
    }
    tsig->next = NULL;
    tsig->name = name;
    tsig->algorithm = algo;
    tsig->secret = secret;
    tsig->key = tsig_key_create(allocator, tsig);
    if (!tsig->key) {
        ods_log_error("[%s] unable to create tsig: tsig_key_create() "
            "failed", tsig_str);
        tsig_cleanup(tsig, allocator);
        return NULL;
    }
    return tsig;
}


/**
 * Clean up TSIG key.
 *
 */
static void
tsig_key_cleanup(tsig_key_type* key, allocator_type* allocator)
{
    if (!key || !allocator) {
        return;
    }
    ldns_rdf_deep_free(key->dname);
    allocator_deallocate(allocator, (void*) key->data);
    return;
}


/**
 * Clean up TSIG.
 *
 */
void
tsig_cleanup(tsig_type* tsig, allocator_type* allocator)
{
    if (!tsig || !allocator) {
        return;
    }
    tsig_cleanup(tsig->next, allocator);
    tsig_key_cleanup(tsig->key, allocator);
    allocator_deallocate(allocator, (void*) tsig->name);
    allocator_deallocate(allocator, (void*) tsig->algorithm);
    allocator_deallocate(allocator, (void*) tsig->secret);
    allocator_deallocate(allocator, (void*) tsig);
    return;
}
