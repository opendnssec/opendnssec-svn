/*
 * $Id: zone.c 4154 2010-11-01 14:01:38Z matthijs $
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
#include "scheduler/schedule.h"
#include "scheduler/task.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/log.h"
#include "signer/zone.h"

#include <ldns/ldns.h>

static const char* zone_str = "zone";

/**
 * Create a new zone.
 *
 */
zone_type*
zone_create(const char* name, ldns_rr_class klass)
{
    allocator_type* allocator = NULL;
    zone_type* zone = NULL;

    if (!name || !klass) {
        ods_log_error("[%s] cannot create zone: no name or class", zone_str);
        return NULL;
    }

    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] cannot create zone %s: create allocator failed",
            zone_str, name);
        return NULL;
    }
    ods_log_assert(allocator);

    zone = (zone_type*) allocator_alloc(allocator, sizeof(zone_type));
    if (!zone) {
        ods_log_error("[%s] cannot create zone %s: allocator failed",
            zone_str, name);
        allocator_cleanup(allocator);
        return NULL;
    }
    ods_log_assert(zone);

    zone->allocator = allocator;
    zone->name = allocator_strdup(allocator, name);
    zone->klass = klass;

    zone->dname = ldns_dname_new_frm_str(name);
    zone->policy_name = NULL;
    zone->signconf_filename = NULL;
    zone->signconf = signconf_create();
    if (!zone->signconf) {
        ods_log_error("[%s] cannot create zone %s: create signconf failed",
            zone_str, name);
        allocator_deallocate(allocator);
        allocator_cleanup(allocator);
        return NULL;
    }
    zone->tobe_removed = 0;
    zone->just_added = 0;
    zone->just_updated = 0;
    zone->task = NULL;
    lock_basic_init(&zone->zone_lock);
    return zone;
}


/**
 * Load signer configuration for zone.
 *
 */
ods_status
zone_load_signconf(zone_type* zone, task_id* tbs)
{
    ods_status status = ODS_STATUS_OK;
    signconf_type* signconf = NULL;
    char* datestamp = NULL;
    uint32_t ustamp = 0;
    task_type* task = NULL;
    task_id what = TASK_SIGN;

    if (!zone) {
        ods_log_error("[%s] cannot load signconf: no zone", zone_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(zone);
    if (!zone->signconf_filename) {
        ods_log_error("[%s] zone %s has no signconf filename, treat as "
            "insecure?", zone_str, zone->name);
        return ODS_STATUS_INSECURE;
    }
    ods_log_assert(zone->signconf_filename);

    status = signconf_update(&signconf, zone->signconf_filename,
        zone->signconf->last_modified);
    if (status == ODS_STATUS_OK) {
        if (!signconf) {
            /* this is unexpected */
            ods_log_error("[%s] cannot load signconf: zone %s signconf %s "
                "storage empty", zone_str, zone->name,
                zone->signconf_filename);
            return ODS_STATUS_ASSERT_ERR;
        }
        ustamp = time_datestamp(signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is modified since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);

        /* do stuff */
        if (zone->task) {
            task = (task_type*) zone->task;
            what = task->what;
        }
        what = signconf_compare(zone->signconf, signconf, what);
        if (what == TASK_NSECIFY) {
            /* Denial of Existence Rollover */
            what = TASK_READ;
        }
        *tbs = what;
        signconf_cleanup(zone->signconf);
        zone->signconf = signconf;
        signconf_log(zone->signconf, zone->name);
    } else if (status == ODS_STATUS_UNCHANGED) {
        ustamp = time_datestamp(zone->signconf->last_modified, "%Y-%m-%d %T",
            &datestamp);
        ods_log_debug("[%s] zone %s signconf file %s is unchanged since %s",
            zone_str, zone->name, zone->signconf_filename,
            datestamp?datestamp:"Unknown");
        free((void*)datestamp);
    } else {
        ods_log_error("[%s] cannot load signconf: zone %s signconf %s: %s",
            zone_str, zone->name, zone->signconf_filename,
            ods_status2str(status));
    }
    return status;
}


/**
 * Merge zones.
 *
 */
void
zone_merge(zone_type* z1, zone_type* z2)
{
    const char* str;

    if (!z1 || !z2) {
        return;
    }

    /* policy name */
    if (ods_strcmp(z2->policy_name, z1->policy_name) != 0) {
        if (z2->policy_name) {
            str = strdup(z2->policy_name);
            if (!str) {
                ods_log_error("[%s] failed to merge policy %s name to zone %s",
                    zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->policy_name);
                z1->policy_name = str;
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->policy_name);
            z1->policy_name = NULL;
            z1->just_updated = 1;
        }
    }

    /* signconf filename */
    if (ods_strcmp(z2->signconf_filename, z1->signconf_filename) != 0) {
        if (z2->signconf_filename) {
            str = strdup(z2->signconf_filename);
            if (!str) {
                ods_log_error("[%s] failed to merge signconf filename %s to "
                    "zone %s", zone_str, z2->policy_name, z1->name);
            } else {
                free((void*)z1->signconf_filename);
                z1->signconf_filename = str;
                z1->just_updated = 1;
            }
        } else {
            free((void*)z1->signconf_filename);
            z1->signconf_filename = NULL;
            z1->just_updated = 1;
        }
    }

    return;
}


/**
 * Clean up a zone.
 *
 */
void
zone_cleanup(zone_type* zone)
{
    allocator_type* allocator;
    lock_basic_type zone_lock;

    if (!zone) {
        return;
    }

    allocator = zone->allocator;
    zone_lock = zone->zone_lock;

    if (zone->dname) {
        ldns_rdf_deep_free(zone->dname);
        zone->dname = NULL;
    }
    if (zone->policy_name) {
        free((void*)zone->policy_name);
        zone->policy_name = NULL;
    }
    if (zone->signconf_filename) {
        free((void*)zone->signconf_filename);
        zone->signconf_filename = NULL;
    }

    signconf_cleanup(zone->signconf);
    allocator_deallocate(allocator);
    allocator_cleanup(allocator);
    lock_basic_destroy(&zone_lock);
    return;
}


/**
 * Print zone.
 *
 */
void
zone_print(FILE* out, zone_type* zone)
{
    ods_log_assert(out);
    ods_log_assert(zone);

    if (1) {
        fprintf(out, "print zonedata TODO\n");
    }
    return;
}
