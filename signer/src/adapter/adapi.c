/*
 * $Id$
 *
 * Copyright (c) 2009-2011 NLNet Labs. All rights reserved.
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
 *
 * Adapter API.
 */

#include "config.h"
#include "adapter/adapi.h"
#include "shared/duration.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

/* static const char* adapi_str = "adapter"; */


/**
 * Get the inbound serial.
 *
 */
uint32_t
adapi_get_serial(zone_type* zone)
{
    if (!zone || !zone->db) {
        return 0;
    }
    return zone->db->inbserial;
}


/**
 * Set the inbound serial.
 *
 */
void
adapi_set_serial(zone_type* zone, uint32_t serial)
{
    if (!zone || !zone->db) {
        return;
    }
    zone->db->inbserial = serial;
    return;
}


/**
 * Get origin.
 *
 */
ldns_rdf*
adapi_get_origin(zone_type* zone)
{
    if (!zone) {
        return NULL;
    }
    return zone->apex;
}


/**
 * Get class.
 *
 */
ldns_rr_class
adapi_get_class(zone_type* zone)
{
    if (!zone) {
        return LDNS_RR_CLASS_IN;
    }
    return zone->klass;
}


/**
 * Get ttl.
 *
 */
uint32_t
adapi_get_ttl(zone_type* zone)
{
    if (!zone) {
        return 0;
    }
    return zone->default_ttl;
}


/*
 * Do full zone transaction.
 *
 */
void
adapi_trans_full(zone_type* zone)
{
    if (!zone || !zone->db) {
    }
    namedb_diff(zone->db);
    return;
}


/*
 * Do incremental zone transaction.
 *
 */
void
adapi_trans_diff(zone_type* zone)
{
    if (!zone || !zone->db) {
        return;
    }
    /* todo */
    return;
}


/**
 * Add RR.
 *
 */
ods_status
adapi_add_rr(zone_type* zone, ldns_rr* rr)
{
    return zone_add_rr(zone, rr, 1);
}


/**
 * Delete RR.
 *
 */
ods_status
adapi_del_rr(zone_type* zone, ldns_rr* rr)
{
    return zone_del_rr(zone, rr, 1);
}


/**
 * Print zone.
 *
 */
void
adapi_printzone(FILE* fd, zone_type* zone)
{
    if (!fd || !zone || !zone->db) {
        return;
    }
    namedb_export(fd, zone->db);
    return;
}
