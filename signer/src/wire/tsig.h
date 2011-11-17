/*
 * $Id: tsig.h 4958 2011-04-18 07:11:09Z matthijs $
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

#ifndef WIRE_TSIG_H
#define WIRE_TSIG_H

#include "config.h"
#include "shared/allocator.h"

/**
 * TSIG.
 *
 */
typedef struct tsig_struct tsig_type;
struct tsig_struct {
    const char* name;
    const char* algorithm;
    const char* secret;
    void* key;
};

/**
 * Create new TSIG.
 * \param[in] allocator memory allocator
 * \param[in] name tsig name
 * \param[in] algo tsig algorithm
 * \param[in] secret tsig secret
 * \return tsig_type* TSIG
 *
 */
tsig_type* tsig_create(allocator_type* allocator, char* name, char* algo,
    char* secret);

/**
 * Clean up TSIG.
 * \param[in] tsig TSIG
 * \param[in] allocator memory allocator
 *
 */
void tsig_cleanup(tsig_type* tsig, allocator_type* allocator);

#endif /* WIRE_TSIG_H */
