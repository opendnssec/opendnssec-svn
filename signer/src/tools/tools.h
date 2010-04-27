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

#include <stdio.h>
#include <stdint.h>

#include "signer/se_key.h"
#include "signer/zone.h"
#include "util/duration.h"

int tools_sorter(const char* filename, char* outfilename,
    const char* zonename, duration_type* soa_min, duration_type* sc_dnskey_ttl);

/*

ldns_status
tools_create_dnskey(const char* zonename, keylist_type* keys,
    ldns_rr_class klass, uint32_t ttl);

int tools_zone_reader(char* filename, char* outfilename,
    char* dnskeyfilename, const char* zonename, ldns_rr_class klass,
    bool use_nsec3, bool has_nsec3param, int nsec3_algo,
    uint16_t nsec3_iter, const char* salt);

int tools_nseccer(char* filename, char* outfilename, duration_type* soa_min);

int tools_nsec3er(char* filename, char* outfilename, const char* zonename,
    duration_type* soa_min, uint8_t algorithm, uint8_t flags, bool optout,
    size_t iterations, const char* salt);

int tools_signer(char* filename, char* outfilename, char* prevfilename, zone_type* zone);

int tools_finalizer(char* filename, char* outfilename);

*/
