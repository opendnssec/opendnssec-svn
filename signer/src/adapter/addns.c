/*
 * $Id: addns.c 5237 2011-06-20 13:05:39Z matthijs $
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
 * DNS Adapters.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/adapter.h"
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "parser/addnsparser.h"
#include "parser/confparser.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"
#include "wire/notify.h"
#include "wire/xfrd.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

static const char* adapter_str = "adapter";
static ods_status addns_read_file(FILE* fd, zone_type* zone);


/**
 * Read the next RR from zone file.
 *
 */
ldns_rr*
addns_read_rr(FILE* fd, char* line, ldns_rdf** orig, ldns_rdf** prev,
    uint32_t* ttl, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    int len = 0;
    uint32_t new_ttl = 0;

addns_read_line:
    if (ttl) {
        new_ttl = *ttl;
    }
    len = adutil_readline_frm_file(fd, line, l);
    adutil_rtrim_line(line, &len);
    if (len >= 0) {
        switch (line[0]) {
            /* no directives */

            /* comments, empty lines */
            case ';':
            case '\n':
                goto addns_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
                if (adutil_whitespace_line(line, len)) {
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                }
                *status = ldns_rr_new_frm_str(&rr, line, new_ttl, *orig, prev);
                if (*status == LDNS_STATUS_OK) {
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    *status = LDNS_STATUS_OK;
                    goto addns_read_line; /* perhaps next line is rr */
                    break;
                } else {
                    ods_log_error("[%s] error parsing RR at line %i (%s): %s",
                        adapter_str, l&&*l?*l:0,
                        ldns_get_errorstr_by_id(*status), line);
                    while (len >= 0) {
                        len = adutil_readline_frm_file(fd, line, l);
                    }
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    return NULL;
                }
                break;
        }
    }
    /* -1, EOF */
    *status = LDNS_STATUS_OK;
    return NULL;
}


/**
 * Read IXFR from file.
 *
 */
static ods_status
addns_read_file(FILE* fd, zone_type* zone)
{
    ldns_rr* rr = NULL;
    uint32_t new_serial = 0;
    uint32_t old_serial = 0;
    uint32_t tmp_serial = 0;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    uint32_t ttl = 0;
    size_t rr_count = 0;
    ods_status result = ODS_STATUS_OK;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned is_axfr = 0;
    unsigned del_mode = 0;
    unsigned soa_seen = 0;
    unsigned line_update_interval = 100000;
    unsigned line_update = line_update_interval;
    unsigned l = 0;

    ods_log_assert(fd);
    ods_log_assert(zone);

    /* $ORIGIN <zone name> */
    dname = adapi_get_origin(zone);
    if (!dname) {
        ods_log_error("[%s] error getting default value for $ORIGIN",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    orig = ldns_rdf_clone(dname);
    if (!orig) {
        ods_log_error("[%s] error setting default value for $ORIGIN",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    /* $TTL <default ttl> */
    ttl = adapi_get_ttl(zone);
    /* read RRs */
    while ((rr = addns_read_rr(fd, line, &orig, &prev, &ttl, &status, &l))
        != NULL) {
        /* check status */
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RR at line %i (%s): %s",
                adapter_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            break;
        }
        /* debug update */
        if (l > line_update) {
            ods_log_debug("[%s] ...at line %i: %s", adapter_str, l, line);
            line_update += line_update_interval;
        }
        /* first RR: check if SOA and correct zone & serialno */
        if (rr_count == 0) {
            rr_count++;
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
                ods_log_error("[%s] bad xfr, first rr is not soa",
                    adapter_str);
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_ERR;
                break;
            }
            soa_seen++;
            if (ldns_dname_compare(ldns_rr_owner(rr), zone->apex)) {
                ods_log_error("[%s] bad xfr, soa dname not equal to zone "
                    "dname %s", adapter_str, zone->name);
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_ERR;
                break;
            }
            tmp_serial =
                ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
            old_serial = adapi_get_serial(zone);
            if (!util_serial_gt(tmp_serial, old_serial)) {
                ods_log_info("[%s] zone %s is already up to date, have "
                    "serial %u, got serial %u", adapter_str, zone->name,
                    old_serial, tmp_serial);
                new_serial = tmp_serial;
                ldns_rr_free(rr);
                rr = NULL;
                result = ODS_STATUS_UNCHANGED;
                break;
            }
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_OK;
            continue;
        }
        /* second RR: if not soa, this is an AXFR */
        if (rr_count == 1) {
            if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA) {
                ods_log_verbose("[%s] detected axfr serial=%u for zone %s",
                    adapter_str, tmp_serial, zone->name);
                new_serial = tmp_serial;
                is_axfr = 1;
                del_mode = 0;
            } else {
                ods_log_verbose("[%s] detected ixfr serial=%u for zone %s",
                    adapter_str, tmp_serial, zone->name);
                new_serial = tmp_serial;
                tmp_serial =
                  ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
                ldns_rr_free(rr);
                rr = NULL;
                rr_count++;
                if (tmp_serial < new_serial) {
                    del_mode = 1;
                    result = ODS_STATUS_OK;
                    continue;
                } else {
                    ods_log_error("[%s] bad xfr for zone %s, bad soa serial",
                        adapter_str, zone->name);
                    result = ODS_STATUS_ERR;
                    break;
                }
            }
        }
        /* soa means swap */
        rr_count++;
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_SOA) {
            if (!is_axfr) {
                tmp_serial =
                  ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
                if (tmp_serial <= new_serial) {
                    if (tmp_serial == new_serial) {
                        soa_seen++;
                    }
                    del_mode = !del_mode;
                    ldns_rr_free(rr);
                    rr = NULL;
                    result = ODS_STATUS_OK;
                    continue;
                } else {
                    ods_log_assert(tmp_serial > new_serial);
                    ods_log_error("[%s] bad xfr for zone %s, bad soa serial",
                        adapter_str, zone->name);
                    ldns_rr_free(rr);
                    rr = NULL;
                    result = ODS_STATUS_ERR;
                    break;
                }
            } else {
               /* for axfr */
               soa_seen++;
            }
        }
        /* [add to/remove from] the zone */
        if (!is_axfr && del_mode) {
            ods_log_debug("[%s] delete RR #%i at line %i: %s",
                adapter_str, rr_count, l, line);
            result = adapi_del_rr(zone, rr);
            ldns_rr_free(rr);
            rr = NULL;
        } else {
            ods_log_debug("[%s] add RR #%i at line %i: %s",
                adapter_str, rr_count, l, line);
            result = adapi_add_rr(zone, rr);
        }
        if (result == ODS_STATUS_UNCHANGED) {
            ods_log_debug("[%s] skipping RR at line %i (%s): %s",
                adapter_str, l, del_mode?"not found":"duplicate", line);
            ldns_rr_free(rr);
            rr = NULL;
            result = ODS_STATUS_OK;
            continue;
        } else if (result != ODS_STATUS_OK) {
            ods_log_error("[%s] error %s RR at line %i: %s",
                adapter_str, del_mode?"deleting":"adding", l, line);
            ldns_rr_free(rr);
            rr = NULL;
            break;
        }
    }
    /* and done */
    if (orig) {
        ldns_rdf_deep_free(orig);
        orig = NULL;
    }
    if (prev) {
        ldns_rdf_deep_free(prev);
        prev = NULL;
    }
    if (result == ODS_STATUS_OK && status != LDNS_STATUS_OK) {
        ods_log_error("[%s] error reading RR at line %i (%s): %s",
            adapter_str, l, ldns_get_errorstr_by_id(status), line);
        result = ODS_STATUS_ERR;
    }
    /* check the number of SOAs seen */
    if (result == ODS_STATUS_OK) {
        if ((is_axfr && soa_seen != 2) || (!is_axfr && soa_seen != 3)) {
            ods_log_error("[%s] bad %s, wrong number of SOAs (%u)",
                adapter_str, is_axfr?"axfr":"ixfr", soa_seen);
            result = ODS_STATUS_ERR;
        }
    }
    /* input zone ok, set inbound serial and apply differences */
    if (result == ODS_STATUS_OK || result == ODS_STATUS_UNCHANGED) {
        adapi_set_serial(zone, new_serial);
        if (is_axfr) {
            adapi_trans_full(zone);
        } else {
            adapi_trans_diff(zone);
        }
        if (result == ODS_STATUS_UNCHANGED) {
            result = ODS_STATUS_OK;
        }
    }
    return result;
}


/**
 * Create DNS input adapter.
 *
 */
dnsin_type*
dnsin_create(void)
{
    dnsin_type* addns = NULL;
    allocator_type* allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create dnsin: allocator_create() "
            " failed", adapter_str);
        return NULL;
    }
    addns = (dnsin_type*) allocator_alloc(allocator, sizeof(dnsin_type));
    if (!addns) {
        ods_log_error("[%s] unable to create dnsin: allocator_alloc() "
            " failed", adapter_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    addns->allocator = allocator;
    addns->request_xfr = NULL;
    addns->allow_notify = NULL;
    addns->tsig = NULL;
    return addns;
}


/**
 * Create DNS output adapter.
 *
 */
dnsout_type*
dnsout_create(void)
{
    dnsout_type* addns = NULL;
    allocator_type* allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to create dnsout: allocator_create() "
            " failed", adapter_str);
        return NULL;
    }
    addns = (dnsout_type*) allocator_alloc(allocator, sizeof(dnsout_type));
    if (!addns) {
        ods_log_error("[%s] unable to create dnsout: allocator_alloc() "
            " failed", adapter_str);
        allocator_cleanup(allocator);
        return NULL;
    }
    addns->allocator = allocator;
    addns->provide_xfr = NULL;
    addns->do_notify = NULL;
    addns->tsig = NULL;
    return addns;
}


/**
 * Read DNS input adapter.
 *
 */
static ods_status
dnsin_read(dnsin_type* addns, const char* filename)
{
    const char* rngfile = ODS_SE_RNGDIR "/addns.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;
    if (!filename || !addns) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] read dnsin file %s", adapter_str, filename);
    status = parse_file_check(filename, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read dnsin: parse error in "
            "file %s (%s)", adapter_str, filename, ods_status2str(status));
        return status;
    }
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        addns->tsig = parse_addns_tsig(addns->allocator, filename);
        addns->request_xfr = parse_addns_request_xfr(addns->allocator,
            filename, addns->tsig);
        addns->allow_notify = parse_addns_allow_notify(addns->allocator,
            filename, addns->tsig);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read dnsout: failed to open file %s",
        adapter_str, filename);
    return ODS_STATUS_ERR;
}


/**
 * Update DNS input adapter.
 *
 */
ods_status
dnsin_update(dnsin_type** addns, const char* filename, time_t* last_mod)
{
    dnsin_type* new_addns = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!filename || !addns || !last_mod) {
        return ODS_STATUS_UNCHANGED;
    }
    /* is the file updated? */
    st_mtime = ods_file_lastmodified(filename);
    if (st_mtime <= *last_mod) {
        ods_log_debug("[%s] dnsin acl not modified", adapter_str);
        return ODS_STATUS_UNCHANGED;
    }
    /* if so, read the new signer configuration */
    new_addns = dnsin_create();
    if (!new_addns) {
        ods_log_error("[%s] unable to update dnsin: dnsin_create() "
            "failed", adapter_str);
        return ODS_STATUS_ERR;
    }
    status = dnsin_read(new_addns, filename);
    if (status == ODS_STATUS_OK) {
        *addns = new_addns;
        *last_mod = st_mtime;
    } else {
        ods_log_error("[%s] unable to update dnsin: dnsin_read(%s) "
            "failed (%s)", adapter_str, filename, ods_status2str(status));
        dnsin_cleanup(new_addns);
    }
    return status;
}

/**
 * Read DNS output adapter.
 *
 */
static ods_status
dnsout_read(dnsout_type* addns, const char* filename)
{
    const char* rngfile = ODS_SE_RNGDIR "/addns.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;
    if (!filename || !addns) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_debug("[%s] read dnsout file %s", adapter_str, filename);
    status = parse_file_check(filename, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read dnsout: parse error in "
            "file %s (%s)", adapter_str, filename, ods_status2str(status));
        return status;
    }
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        addns->tsig = parse_addns_tsig(addns->allocator, filename);
        addns->provide_xfr = parse_addns_provide_xfr(addns->allocator,
            filename, addns->tsig);
        addns->do_notify = parse_addns_do_notify(addns->allocator, filename,
            addns->tsig);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }
    ods_log_error("[%s] unable to read dnsout: failed to open file %s",
        adapter_str, filename);
    return ODS_STATUS_ERR;
}


/**
 * Update DNS output adapter.
 *
 */
ods_status
dnsout_update(dnsout_type** addns, const char* filename, time_t* last_mod)
{
    dnsout_type* new_addns = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!filename || !addns || !last_mod) {
        return ODS_STATUS_UNCHANGED;
    }
    /* is the file updated? */
    st_mtime = ods_file_lastmodified(filename);
    if (st_mtime <= *last_mod) {
        ods_log_debug("[%s] dnsout acl not modified", adapter_str);
        return ODS_STATUS_UNCHANGED;
    }
    /* if so, read the new signer configuration */
    new_addns = dnsout_create();
    if (!new_addns) {
        ods_log_error("[%s] unable to update dnsout: dnsout_create() "
            "failed", adapter_str);
        return ODS_STATUS_ERR;
    }
    status = dnsout_read(new_addns, filename);
    if (status == ODS_STATUS_OK) {
        *addns = new_addns;
        *last_mod = st_mtime;
    } else {
        ods_log_error("[%s] unable to update dnsout: dnsout_read(%s) "
            "failed (%s)", adapter_str, filename, ods_status2str(status));
        dnsout_cleanup(new_addns);
    }
    return status;
}


/**
 * Send notifies.
 *
 */
static void
dnsout_send_notify(void* zone)
{
    zone_type* z = (zone_type*) zone;
    if (!z->notify) {
        ods_log_error("[%s] unable to send notify for zone %s: no notify "
           "handler", adapter_str, z->name);
        return;
    }
    ods_log_assert(z);
    ods_log_assert(z->adoutbound);
    ods_log_assert(z->adoutbound->config);
    ods_log_assert(z->adoutbound->type == ADAPTER_DNS);
    ods_log_assert(z->db);
    ods_log_assert(z->name);
    ods_log_debug("[%s] enable notify for zone %s serial %u", adapter_str,
        z->name, z->db->intserial);
    notify_enable(z->notify, z->db->intserial);
    return;
}


/**
 * Read zone from DNS Input Adapter.
 *
 */
ods_status
addns_read(void* zone)
{
    zone_type* z = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;
    char* xfrfile = NULL;
    FILE* fd = NULL;
    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->xfrd);
    ods_log_assert(z->db);
    ods_log_assert(z->adinbound);
    ods_log_assert(z->adinbound->type == ADAPTER_DNS);

    if (!z->xfrd->serial_disk_acquired) {
        return ODS_STATUS_UNCHANGED;
    }

    lock_basic_lock(&z->xfrd->rw_lock);
    xfrfile = ods_build_path(z->name, ".xfrd", 0);
    fd = ods_fopen(xfrfile, NULL, "r");
    free((void*) xfrfile);
    if (!fd) {
        lock_basic_unlock(&z->xfrd->rw_lock);
        return ODS_STATUS_FOPEN_ERR;
    }
    status = addns_read_file(fd, z);
    if (status == ODS_STATUS_OK) {
        lock_basic_lock(&z->xfrd->serial_lock);
        z->xfrd->serial_xfr = adapi_get_serial(z);
        z->xfrd->serial_xfr_acquired = z->xfrd->serial_disk_acquired;
        lock_basic_unlock(&z->xfrd->serial_lock);
    }
    ods_fclose(fd);
    lock_basic_unlock(&z->xfrd->rw_lock);
    return status;
}


/**
 * Write to DNS Output Adapter.
 *
 */
ods_status
addns_write(void* zone, const char* filename)
{
    FILE* fd = NULL;
    char* atmpfile = NULL;
    char* axfrfile = NULL;
    char* itmpfile = NULL;
    char* ixfrfile = NULL;
    zone_type* z = (zone_type*) zone;
    int ret = 0;
    ods_log_assert(z);
    ods_log_assert(z->name);
    ods_log_assert(z->adoutbound);
    ods_log_assert(z->adoutbound->type == ADAPTER_DNS);

    atmpfile = ods_build_path(z->name, ".axfr.tmp", 0);
    fd = ods_fopen(atmpfile, NULL, "w");
    if (!fd) {
        free((void*) atmpfile);
        return ODS_STATUS_FOPEN_ERR;
    }
    adapi_printaxfr(fd, z);
    ods_fclose(fd);

    itmpfile = ods_build_path(z->name, ".ixfr.tmp", 0);
    fd = ods_fopen(itmpfile, NULL, "w");
    if (!fd) {
        free((void*) atmpfile);
        free((void*) itmpfile);
        return ODS_STATUS_FOPEN_ERR;
    }
    adapi_printixfr(fd, z);
    ods_fclose(fd);

    /* lock and move */
    axfrfile = ods_build_path(z->name, ".axfr", 0);
    lock_basic_lock(&z->xfr_lock);
    ret = rename(atmpfile, axfrfile);
    if (ret != 0) {
        ods_log_error("[%s] unable to rename file %s to %s: %s", adapter_str,
            atmpfile, axfrfile, strerror(errno));
        lock_basic_unlock(&z->xfr_lock);
        free((void*) atmpfile);
        free((void*) axfrfile);
        free((void*) itmpfile);
        return ODS_STATUS_RENAME_ERR;
    }
    free((void*) atmpfile);
    free((void*) axfrfile);
    ixfrfile = ods_build_path(z->name, ".ixfr", 0);
    ret = rename(itmpfile, ixfrfile);
    if (ret != 0) {
        ods_log_error("[%s] unable to rename file %s to %s: %s", adapter_str,
            itmpfile, ixfrfile, strerror(errno));
        lock_basic_unlock(&z->xfr_lock);
        free((void*) itmpfile);
        free((void*) ixfrfile);
        return ODS_STATUS_RENAME_ERR;
    }
    free((void*) itmpfile);
    free((void*) ixfrfile);
    lock_basic_unlock(&z->xfr_lock);

    dnsout_send_notify(zone);
    return ODS_STATUS_OK;
}


/**
 * Clean up DNS input adapter.
 *
 */
void
dnsin_cleanup(dnsin_type* addns)
{
    allocator_type* allocator = NULL;
    if (!addns) {
        return;
    }
    allocator = addns->allocator;
    acl_cleanup(addns->request_xfr, allocator);
    acl_cleanup(addns->allow_notify, allocator);
    tsig_cleanup(addns->tsig, allocator);
    allocator_deallocate(allocator, (void*) addns);
    allocator_cleanup(allocator);
    return;
}


/**
 * Clean up DNS output adapter.
 *
 */
void
dnsout_cleanup(dnsout_type* addns)
{
    allocator_type* allocator = NULL;
    if (!addns) {
        return;
    }
    allocator = addns->allocator;
    acl_cleanup(addns->provide_xfr, allocator);
    acl_cleanup(addns->do_notify, allocator);
    tsig_cleanup(addns->tsig, allocator);
    allocator_deallocate(allocator, (void*) addns);
    allocator_cleanup(allocator);
    return;
}
