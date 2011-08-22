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
 * File Adapters.
 *
 */

#include "config.h"
#include "adapter/adapi.h"
#include "adapter/adfile.h"
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
static ods_status adfile_read_file(FILE* fd, zone_type* zone);


/**
 * Initialize file adapters.
 *
 */
ods_status
adfile_init(const char* configstr)
{
    if (configstr) {
        ods_log_warning("[%s] File Adapter init not implemented %s",
            adapter_str);
    }
    return ODS_STATUS_OK;
}


/**
 * Read the next RR from zone file.
 *
 */
static ldns_rr*
adfile_read_rr(FILE* fd, zone_type* zone, char* line, ldns_rdf** orig,
    ldns_rdf** prev, uint32_t* ttl, ldns_status* status, unsigned int* l)
{
    ldns_rr* rr = NULL;
    ldns_rdf* tmp = NULL;
    FILE* fd_include = NULL;
    int len = 0;
    ods_status s = ODS_STATUS_OK;
    uint32_t new_ttl = 0;
    const char *endptr;  /* unused */
    int offset = 0;

adfile_read_line:
    if (ttl) {
        new_ttl = *ttl;
    }

    len = adutil_readline_frm_file(fd, line, l);
    adutil_rtrim_line(line, &len);

    if (len >= 0) {
        switch (line[0]) {
            /* directive */
            case '$':
                if (strncmp(line, "$ORIGIN", 7) == 0 && isspace(line[7])) {
                    /* copy from ldns */
                    if (*orig) {
                        ldns_rdf_deep_free(*orig);
                        *orig = NULL;
                    }
                    offset = 8;
                    while (isspace(line[offset])) {
                        offset++;
                    }
                    tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME,
                        line + offset);
                    if (!tmp) {
                        /* could not parse what next to $ORIGIN */
                        *status = LDNS_STATUS_SYNTAX_DNAME_ERR;
                        return NULL;
                    }
                    *orig = tmp;
                    /* end copy from ldns */
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                } else if (strncmp(line, "$TTL", 4) == 0 &&
                    isspace(line[4])) {
                    /* override default ttl */
                    offset = 5;
                    while (isspace(line[offset])) {
                        offset++;
                    }
                    if (ttl) {
                        *ttl = ldns_str2period(line + offset, &endptr);
                        new_ttl = *ttl;
                    }
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                } else if (strncmp(line, "$INCLUDE", 8) == 0 &&
                    isspace(line[8])) {
                    /* dive into this file */
                    offset = 9;
                    while (isspace(line[offset])) {
                        offset++;
                    }
                    fd_include = ods_fopen(line + offset, NULL, "r");
                    if (fd_include) {
                        s = adfile_read_file(fd_include, zone);
                        ods_fclose(fd_include);
                    } else {
                        ods_log_error("[%s] unable to open include file %s",
                            adapter_str, (line+offset));
                        *status = LDNS_STATUS_SYNTAX_ERR;
                        return NULL;
                    }
                    if (s != ODS_STATUS_OK) {
                        *status = LDNS_STATUS_SYNTAX_ERR;
                        ods_log_error("[%s] error in include file %s",
                            adapter_str, (line+offset));
                        return NULL;
                    }
                    /* restore current ttl */
                    if (ttl) {
                        *ttl = new_ttl;
                    }
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                }
                goto adfile_read_rr; /* this can be an owner name */
                break;
            /* comments, empty lines */
            case ';':
            case '\n':
                goto adfile_read_line; /* perhaps next line is rr */
                break;
            /* let's hope its a RR */
            default:
adfile_read_rr:
                if (adutil_whitespace_line(line, len)) {
                    goto adfile_read_line; /* perhaps next line is rr */
                    break;
                }

                *status = ldns_rr_new_frm_str(&rr, line, new_ttl, *orig, prev);
                if (*status == LDNS_STATUS_OK) {
                    ldns_rr2canonical(rr); /* TODO: canonicalize or not? */
                    return rr;
                } else if (*status == LDNS_STATUS_SYNTAX_EMPTY) {
                    if (rr) {
                        ldns_rr_free(rr);
                        rr = NULL;
                    }
                    *status = LDNS_STATUS_OK;
                    goto adfile_read_line; /* perhaps next line is rr */
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
 * Read zone file.
 *
 */
static ods_status
adfile_read_file(FILE* fd, zone_type* zone)
{
    ods_status result = ODS_STATUS_OK;
    ldns_rr* rr = NULL;
    ldns_rdf* prev = NULL;
    ldns_rdf* orig = NULL;
    ldns_rdf* dname = NULL;
    uint32_t ttl = 0;
    ldns_status status = LDNS_STATUS_OK;
    char line[SE_ADFILE_MAXLINE];
    unsigned int line_update_interval = 100000;
    unsigned int line_update = line_update_interval;
    unsigned int l = 0;

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
    while ((rr = adfile_read_rr(fd, zone, line, &orig, &prev, &ttl,
        &status, &l)) != NULL) {

        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] error reading RR at line %i (%s): %s",
                adapter_str, l, ldns_get_errorstr_by_id(status), line);
            result = ODS_STATUS_ERR;
            break;
        }

        if (l > line_update) {
            ods_log_debug("[%s] ...at line %i: %s", adapter_str, l, line);
            line_update += line_update_interval;
        }

        /* filter out DNSSEC RRs (except DNSKEY) from the Input File Adapter */
        if (util_is_dnssec_rr(rr)) {
            ldns_rr_free(rr);
            rr = NULL;
            continue;
        }

        /* add to the zonedata */
        result = adapi_add_rr(zone, rr);
        if (result != ODS_STATUS_OK) {
            ods_log_error("[%s] error adding RR at line %i: %s",
                adapter_str, l, line);
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
    return result;
}


/**
 * Read zone from zonefile.
 *
 */
ods_status
adfile_read(struct zone_struct* zone, const char* filename)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;
    uint32_t new_serial = 0;
    ldns_rr* rr = NULL;

    /* [start] sanity parameter checking */
    if (!adzone) {
        ods_log_error("[%s] unable to read file: no zone (or no name given)",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    if (!filename) {
        ods_log_error("[%s] unable to read file: no filename given",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(filename);
    /* [end] sanity parameter checking */

    /* [start] read zone */
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        /* serial */
        rr = adutil_lookup_soa_rr(fd);
        if (rr) {
            new_serial =
                ldns_rdf2native_int32(ldns_rr_rdf(rr, SE_SOA_RDATA_SERIAL));
        }
        ldns_rr_free(rr);
        rewind(fd);

        status = adfile_read_file(fd, adzone);
        ods_fclose(fd);
    } else {
        status = ODS_STATUS_FOPEN_ERR;
    }
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read file: %s", adapter_str,
            ods_status2str(status));
        return status;
    }
    /* [end] read zone */

    /* [start] full transaction */
    status = adapi_trans_full(adzone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read file: start transaction failed",
            adapter_str);
        return status;
    }
    /* [end] full transaction */

    /* [start] validate updates */
    status = zone_examine(adzone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to read file: zonefile contains errors",
            adapter_str);
        return status;
    }
    /* [end] validate updates */
    adapi_set_serial(adzone, new_serial);
    return ODS_STATUS_OK;
}


/**
 * Read zone from backup file.
 *
 */
ods_status
adbackup_read(struct zone_struct* zone, const char* filename)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    /* [start] sanity parameter checking */
    if (!adzone) {
        ods_log_error("[%s] unable to read file: no zone (or no name given)",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    if (!filename) {
        ods_log_error("[%s] unable to read file: no filename given",
            adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(filename);
    /* [end] sanity parameter checking */

    /* [start] read zone */
    fd = ods_fopen(filename, NULL, "r");
    if (fd) {
        status = adfile_read_file(fd, adzone);
        ods_fclose(fd);
    } else {
        status = ODS_STATUS_FOPEN_ERR;
    }
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to recover file: %s", adapter_str,
            ods_status2str(status));
        return status;
    }
    /* [end] read zone */

    /* [start] full transaction */
    status = adapi_trans_full(adzone);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to recover file: start transaction failed",
            adapter_str);
        return status;
    }
    /* [end] full transaction */
    return ODS_STATUS_OK;
}


/**
 * Write zonefile.
 *
 */
ods_status
adfile_write(struct zone_struct* zone, const char* filename)
{
    FILE* fd = NULL;
    zone_type* adzone = (zone_type*) zone;
    ods_status status = ODS_STATUS_OK;

    /* [start] sanity parameter checking */
    if (!adzone) {
        ods_log_error("[%s] unable to write file: no zone (or no "
            "name given)", adapter_str);
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(adzone);
    if (!filename) {
        ods_log_error("[%s] unable to write file: no filename given",
            adapter_str);
        return ODS_STATUS_ERR;
    }
    ods_log_assert(filename);
    /* [end] sanity parameter checking */

    /* [start] write zone */
    fd = ods_fopen(filename, NULL, "w");
    if (fd) {
        status = zone_print(fd, adzone);
        ods_fclose(fd);
    } else {
        status = ODS_STATUS_FOPEN_ERR;
    }
    /* [end] write zone */

    return status;
}
