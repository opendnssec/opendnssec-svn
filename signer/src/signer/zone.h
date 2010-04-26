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
 * Zone.
 *
 */

#ifndef SIGNER_ZONE_H
#define SIGNER_ZONE_H

#include "config.h"
#include "adapter/adapter.h"
#include "scheduler/locks.h"
#include "signer/signconf.h"
#include "signer/zonedata.h"

#include <ldns/ldns.h>

struct task_struct;
struct tasklist_struct;
struct worker_struct;

/**
 * Zone.
 *
 */
typedef struct zone_struct zone_type;
struct zone_struct {
    const char* name; /* string format zone name */
    ldns_rdf* dname; /* wire format zone name */
    ldns_rr_class klass; /* class */
    uint32_t fallback_ttl; /* fallback ttl */
    uint32_t inbound_serial; /* last seen inbound soa serial */
    uint32_t outbound_serial; /* last written outbound soa serial */
    const char* policy_name; /* policy identifier */
    const char* signconf_filename; /* signer configuration filename */
    signconf_type* signconf; /* signer configuration values */
    adapter_type* inbound_adapter; /* inbound adapter */
    adapter_type* outbound_adapter; /* outbound adapter */
    struct task_struct* task; /* current scheduled task */
    struct worker_struct* worker; /* current active worker */
    time_t backoff; /* backoff value if there is something failing with this zone */
    zonedata_type* zonedata; /* zone data */
    int in_progress; /* zone is being worked on (could be checked with current active worker) */
    int just_added;
    int just_updated;
    int tobe_removed;

    lock_basic_type zone_lock;
    lock_basic_type slhelper_lock;
};

/**
 * Create a new zone.
 * \param[in] name zone name
 * \param[in] klass zone class
 * \return zone_type* zone
 *
 */
zone_type* zone_create(const char* name, ldns_rr_class klass);

/**
 * Update zone configuration settings from zone list.
 * \param[in] z1 zone to be updated
 * \param[in] z2 update
 *
 */
void zone_update_zonelist(zone_type* z1, zone_type* z2);

/**
 * Read signer configuration file.
 * \param[in] zone corresponding zone
 * \param[in] tl task list
 * \param[in] buf feedback buffer
 * \return int 0 on success, 1 on error
 *
 */
int zone_update_signconf(zone_type* zone, struct tasklist_struct* tl,
    char* buf);

/**
 * Add a RR to the zone.
 * \param[in] zone zone structure
 * \param[in] rr resource record
 * \return int 0 on success, 1 on error
 *
 */
int zone_add_rr(zone_type* zone, ldns_rr* rr);

/**
 * Clean up a zone.
 * \param[in] zone zone to cleanup
 *
 */
void zone_cleanup(zone_type* zone);

#endif /* SIGNER_ZONE_H */
