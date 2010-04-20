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

#include "adapter/adapter.h" *
#include "scheduler/locks.h"
#include "signer/zone.h"
#include "signer/zonedata.h"
#include "util/file.h"
#include "util/log.h"
#include "util/se_malloc.h"

#include <ldns/ldns.h> /* ldns_dname_new_frm_str(), ldns_rdf_deep_free() */

/* copycode: This define is taken from BIND9 */
#define DNS_SERIAL_GT(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) > 0)


/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(const char* name, ldns_rr_class klass)
{
    zone_type* zone = (zone_type*) se_calloc(1, sizeof(zone_type));

    se_log_assert(name);
    se_log_debug("create zone %s", name);

    /* zone identification */
    zone->name = se_strdup(name);
    zone->dname = ldns_dname_new_frm_str(name);
    zone->klass = klass;
    zone->inbound_serial = 0;
    zone->outbound_serial = 0;
    /* policy */
    zone->fallback_ttl = 3600; /* perhaps set a default ttl in configure */
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->inbound_adapter = NULL;
    zone->outbound_adapter = NULL;
    /* status */
    zone->task = NULL;
    zone->backoff = 0;
    zone->worker = NULL;
    /* zone data */
    zone->zonedata = zonedata_create();

    lock_basic_init(&zone->zone_lock);
    lock_basic_init(&zone->slhelper_lock);
    return zone;
}


/**
 * Clean up a zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    if (zone) {
        if (zone->dname) {
            ldns_rdf_deep_free(zone->dname);
            zone->dname = NULL;
        }
        if (zone->inbound_adapter) {
            adapter_cleanup(zone->inbound_adapter);
            zone->inbound_adapter = NULL;
        }
        if (zone->outbound_adapter) {
            adapter_cleanup(zone->outbound_adapter);
            zone->outbound_adapter = NULL;
        }
        if (zone->zonedata) {
            zonedata_cleanup(zone->zonedata);
            zone->zonedata = NULL;
        }
        if (zone->policy_name) {
            se_free((void*) zone->policy_name);
            zone->policy_name = NULL;
        }
            se_free((void*) zone->signconf_filename);
            se_free((void*) zone->name);

        lock_basic_destroy(&zone->zone_lock);
        lock_basic_destroy(&zone->slhelper_lock);
        se_free((void*) zone);
    } else {
        se_log_warning("cleanup emtpy zone");
    }
}
