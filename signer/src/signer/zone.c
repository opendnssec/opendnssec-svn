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

#include "adapter/adapter.h"
#include "scheduler/locks.h"
#include "signer/signconf.h"
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
    zone->signconf = NULL;
    zone->inbound_adapter = NULL;
    zone->outbound_adapter = NULL;
    /* status */
    zone->task = NULL;
    zone->backoff = 0;
    zone->worker = NULL;
    zone->just_added = 0;
    zone->just_updated = 0;
    zone->tobe_removed = 0;
    zone->in_progress = 0;
    /* zone data */
    zone->zonedata = zonedata_create();

    lock_basic_init(&zone->zone_lock);
    lock_basic_init(&zone->slhelper_lock);
    return zone;
}


/**
 * Update zone configuration settings from zone list.
 *
 */
void
zone_update_zonelist(zone_type* z1, zone_type* z2)
{
    se_log_assert(z1);
    se_log_assert(z2);

    if (se_strcmp(z2->policy_name, z1->policy_name) != 0) {
        se_free((void*)z1->policy_name);
        if (z2->policy_name) {
            z1->policy_name = se_strdup(z2->policy_name);
        } else {
            z1->policy_name = NULL;
        }
        z1->just_updated = 1;
    }

    if (se_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        se_free((void*)z1->signconf_filename);
        if (z2->signconf_filename) {
            z1->signconf_filename = se_strdup(z2->signconf_filename);
        } else {
            z1->signconf_filename = NULL;
        }
        z1->just_updated = 1;
    }

    if (adapter_compare(z1->inbound_adapter, z2->inbound_adapter) != 0) {
        adapter_cleanup(z1->inbound_adapter);
        if (z2->inbound_adapter) {
            z1->inbound_adapter = adapter_create(
                z2->inbound_adapter->filename,
                z2->inbound_adapter->type,
                z2->inbound_adapter->inbound);
        } else {
            z1->inbound_adapter = NULL;
        }
        z1->just_updated = 1;
    }

    if (adapter_compare(z1->outbound_adapter, z2->outbound_adapter) != 0) {
        adapter_cleanup(z1->outbound_adapter);
        if (z2->outbound_adapter) {
            z1->outbound_adapter = adapter_create(
                z2->outbound_adapter->filename,
                z2->outbound_adapter->type,
                z2->outbound_adapter->inbound);
        } else {
            z1->outbound_adapter = NULL;
        }
        z1->just_updated = 1;
    }

    zone_cleanup(z2);
    return;
}


/**
 * Read signer configuration.
 *
 */
int
zone_update_signconf(zone_type* zone, struct tasklist_struct* tl, char* buf)
{
    signconf_type* signconf = NULL;
    time_t last_modified = 0;
    time_t now;
    struct task_struct* task = NULL;

    se_log_assert(zone);
    se_log_debug("load zone signconf %s (%s)", zone->name, zone->signconf_filename);

    if (zone->signconf) {
        last_modified = zone->signconf->last_modified;
    }

    signconf = signconf_read(zone->signconf_filename, last_modified);
    if (!signconf) {
        if (!zone->policy_name) {
            se_log_warning("zone %s has no policy", zone->name);
        } else {
            signconf = signconf_read(zone->signconf_filename, 0);
            if (!signconf) {
                se_log_warning("zone %s has policy %s configured, "
                    "but has no (valid) signconf file",
                    zone->name, zone->policy_name);
                if (buf) {
                    (void)snprintf(buf, ODS_SE_MAXLINE,
                        "Zone %s config has errors.\n", zone->name);
                }
                return -1;
            } else {
                se_log_debug("zone %s has not changed", zone->name);
            }
        }
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config has not changed.\n", zone->name);
        }
        return 0;
    } else if (signconf_check(signconf) != 0) {
        se_log_warning("zone %s signconf has errors", zone->name);
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config has errors.\n", zone->name);
        }
        return -1;
    } else if (!zone->signconf) {
        zone->signconf = signconf;
        /* we don't check if foo in <Zone name="foo"> matches zone->name */
        zone->signconf->name = zone->name;
        se_log_debug("zone %s now has signconf", zone->name);
        /* zone state? */
        /* create task for new zone */
        if (!task) {
            if (buf) {
                (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s now has config, "
                    "but could not be scheduled.\n", zone->name);
            }
        } else {
            if (buf) {
                (void)snprintf(buf, ODS_SE_MAXLINE,
                    "Zone %s now has config.\n", zone->name);
            }
        }
        return 1;
    } else {
        /* update task for new zone */
        signconf_cleanup(zone->signconf);
        zone->signconf = signconf;
        zone->signconf->name = zone->name;
        se_log_debug("zone %s signconf updated", zone->name);
        if (buf) {
            (void)snprintf(buf, ODS_SE_MAXLINE,
                "Zone %s config updated.\n", zone->name);
        }
        return 1;
    }
    /* not reached */
    return 0;
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
