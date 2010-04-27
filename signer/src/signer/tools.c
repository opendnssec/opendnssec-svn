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
 * Zone signing tools.
 *
 */

#include "config.h"
#include "adapter/adapter.h"
#include "daemon/engine.h"
#include "scheduler/locks.h"
#include "signer/tools.h"
#include "signer/zone.h"
#include "tools/tools.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"


/**
 * Read zone's input adapter.
 *
 */
int
tools_read_input(zone_type* zone)
{
    char* tmpname = NULL;
    char* tmpname2 = NULL;
    char* zonename = NULL;
    int result = 0;

    se_log_assert(zone);
    se_log_assert(zone->inbound_adapter);
    se_log_assert(zone->signconf);
    se_log_verbose("read zone %s", zone->name);

    tmpname2 = se_build_path(zone->name, ".unsorted", 0);
    /* make a copy (slooooooow, use system(cp) ?) */
    result = se_file_copy(zone->inbound_adapter->filename, tmpname2);
    if (result == 0) {
        tmpname = se_build_path(zone->name, ".sorted", 0);
        zonename = ldns_rdf2str(zone->dname);
        result = tools_sorter(tmpname2, tmpname,
            zonename, zone->signconf->soa_min, zone->signconf->dnskey_ttl);
        se_free((void*)tmpname);
        se_free((void*)zonename);
    }
    se_free((void*)tmpname2);
    return result;
}
