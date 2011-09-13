/*
 * $Id: addns.c -1   $
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
 * File Adapters.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/adapter.h"
#include "adapter/addns.h"
#include "adapter/adutil.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"
#include "shared/status.h"
#include "shared/util.h"
#include "signer/zone.h"

#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>

static const char* adapter_str = "adapter";
static ods_status addns_read_file(FILE* fd, zone_type* zone);


/**
 * Read the next RR from zone file.
 *
 */
static ldns_rr*
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
    uint32_t tmp_serial = 0;
    uint32_t old_serial = 0;
    uint32_t new_serial = 0;
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
            new_serial =
                ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
            old_serial = adapi_get_serial(zone);
            if (!DNS_SERIAL_GT(new_serial, old_serial)) {
                ods_log_info("[%s] zone %s is already up to date, have "
                    "serial %u, got serial %u", adapter_str, zone->name,
                    old_serial, new_serial);
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
                    adapter_str, new_serial, zone->name);
                is_axfr = 1;
                del_mode = 0;
            } else {
                ods_log_verbose("[%s] detected ixfr serial=%u for zone %s",
                    adapter_str, new_serial, zone->name);
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
 * Read zone from DNS Input Adapter.
 *
 */
ods_status
addns_read(void* zone)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;
    if (!adzone || !adzone->adinbound || !adzone->adinbound->configstr) {
        return ODS_STATUS_ASSERT_ERR;
    }
    fd = ods_fopen(adzone->adinbound->configstr, NULL, "r");
    if (!fd) {
        return ODS_STATUS_FOPEN_ERR;
    }
    status = addns_read_file(fd, adzone);
    ods_fclose(fd);
    return status;
}


/**
 * Write to DNS Output Adapter.
 *
 */
ods_status
addns_write(void* zone, const char* str)
{
    FILE* fd = NULL;
    char ixfrname[SYSTEM_MAXLEN];
    zone_type* adzone = (zone_type*) zone;
    if (!adzone || !str) {
        return ODS_STATUS_ASSERT_ERR;
    }
    fd = ods_fopen(str, NULL, "w");
    if (!fd) {
        ods_log_error("[%s] unable to write zone %s: failed to open file %s "
            "for writing", adapter_str, adzone->name, str);
        return ODS_STATUS_FOPEN_ERR;
    }
    adapi_printzone(fd, adzone);
    ods_fclose(fd);

    snprintf(ixfrname, SYSTEM_MAXLEN, "%s.ixfr", str);
    fd = ods_fopen(ixfrname, NULL, "a");
    if (!fd) {
        ods_log_error("[%s] unable to write zone %s: failed to open file %s "
            "for writing", adapter_str, adzone->name, ixfrname);
        return ODS_STATUS_FOPEN_ERR;
    }
    adapi_printixfr(fd, adzone);
    ods_fclose(fd);
    return ODS_STATUS_OK;
}
