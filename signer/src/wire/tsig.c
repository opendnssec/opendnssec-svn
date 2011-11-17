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
#include "wire/tsig.h"

const char* tsig_str = "tsig";


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
    tsig->key = NULL;
    return tsig;
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
    allocator_deallocate(allocator, (void*) tsig->name);
    allocator_deallocate(allocator, (void*) tsig->algorithm);
    allocator_deallocate(allocator, (void*) tsig->secret);
    allocator_deallocate(allocator, (void*) tsig);
    return;
}
