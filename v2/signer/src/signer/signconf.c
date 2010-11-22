/*
 * $Id: signconf.c 4126 2010-10-18 10:57:46Z matthijs $
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
 * Signer configuration.
 *
 */

#include "parser/confparser.h"
#include "parser/signconfparser.h"
#include "scheduler/task.h"
#include "signer/signconf.h"
#include "shared/duration.h"
#include "shared/file.h"
#include "shared/log.h"

static const char* sc_str = "signconf";


/**
 * Create a new signer configuration with the 'empty' settings.
 *
 */
signconf_type*
signconf_create(void)
{
    signconf_type* sc;
    allocator_type* allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] cannot create: no allocator available", sc_str);
        return NULL;
    }
    ods_log_assert(allocator);

    sc = (signconf_type*) allocator_alloc(allocator, sizeof(signconf_type));
    if (!sc) {
        ods_log_error("[%s] cannot create: allocator failed", sc_str);
        return NULL;
    }
    ods_log_assert(sc);
    sc->allocator = allocator;
    /* Signatures */
    sc->sig_resign_interval = NULL;
    sc->sig_refresh_interval = NULL;
    sc->sig_validity_default = NULL;
    sc->sig_validity_denial = NULL;
    sc->sig_jitter = NULL;
    sc->sig_inception_offset = NULL;
    /* Denial of existence */
    sc->nsec_type = 0;
    sc->nsec3_optout = 0;
    sc->nsec3_algo = 0;
    sc->nsec3_iterations = 0;
    sc->nsec3_salt = NULL;
    /* Keys */
    sc->dnskey_ttl = NULL;
    sc->keys = NULL;
    /* Source of authority */
    sc->soa_ttl = NULL;
    sc->soa_min = NULL;
    sc->soa_serial = NULL;
    /* Other useful information */
    sc->last_modified = 0;
    sc->audit = 0;
    return sc;
}


/**
 * Read signer configuration.
 *
 */
static ods_status
signconf_read(signconf_type* signconf, const char* scfile)
{
    const char* rngfile = ODS_SE_RNGDIR "/signconf.rng";
    ods_status status = ODS_STATUS_OK;
    FILE* fd = NULL;

    ods_log_assert(scfile);
    ods_log_assert(signconf);
    ods_log_debug("[%s] read file %s", sc_str, scfile);

    status = parse_file_check(scfile, rngfile);
    if (status != ODS_STATUS_OK) {
        ods_log_error("[%s] unable to parse file %s: %s", sc_str, scfile,
            ods_status2str(status));
        return status;
    }

    fd = ods_fopen(scfile, NULL, "r");
    if (fd) {
        signconf->filename = allocator_strdup(signconf->allocator, scfile);
        signconf->sig_resign_interval = parse_sc_sig_resign_interval(scfile);
        signconf->sig_refresh_interval = parse_sc_sig_refresh_interval(scfile);
        signconf->sig_validity_default = parse_sc_sig_validity_default(scfile);
        signconf->sig_validity_denial = parse_sc_sig_validity_denial(scfile);
        signconf->sig_jitter = parse_sc_sig_jitter(scfile);
        signconf->sig_inception_offset = parse_sc_sig_inception_offset(scfile);
        signconf->nsec_type = parse_sc_nsec_type(scfile);
        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            signconf->nsec3_optout = parse_sc_nsec3_optout(scfile);
            signconf->nsec3_algo = parse_sc_nsec3_algorithm(scfile);
            signconf->nsec3_iterations = parse_sc_nsec3_iterations(scfile);
            signconf->nsec3_salt = parse_sc_nsec3_salt(signconf->allocator,
                scfile);
        }
        signconf->keys = parse_sc_keys(signconf->allocator, scfile);
        signconf->dnskey_ttl = parse_sc_dnskey_ttl(scfile);
        signconf->soa_ttl = parse_sc_soa_ttl(scfile);
        signconf->soa_min = parse_sc_soa_min(scfile);
        signconf->soa_serial = parse_sc_soa_serial(signconf->allocator,
            scfile);
        signconf->audit = parse_sc_audit(scfile);
        ods_fclose(fd);
        return ODS_STATUS_OK;
    }

    ods_log_error("[%s] unable to read signconf file %s", sc_str, scfile);
    return ODS_STATUS_ERR;
}


/**
 * Update signer configuration.
 *
 */
ods_status
signconf_update(signconf_type** signconf, const char* scfile,
    time_t last_modified)
{
    signconf_type* new_sc = NULL;
    time_t st_mtime = 0;
    ods_status status = ODS_STATUS_OK;

    if (!signconf) {
        ods_log_error("[%s] no signconf storage", sc_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(signconf);
    if (!scfile) {
        ods_log_error("[%s] no signconf filename", sc_str);
        return ODS_STATUS_UNCHANGED;
    }
    ods_log_assert(scfile);

    /* is the file updated? */
    st_mtime = ods_file_lastmodified(scfile);
    if (st_mtime <= last_modified) {
        return ODS_STATUS_UNCHANGED;
    }

    new_sc = signconf_create();
    if (!new_sc) {
        ods_log_error("[%s] error creating new zone list", sc_str);
        return ODS_STATUS_ERR;
    }

    status = signconf_read(new_sc, scfile);
    if (status == ODS_STATUS_OK) {
        new_sc->last_modified = st_mtime;
        if (signconf_check(new_sc) != ODS_STATUS_OK) {
            ods_log_error("[%s] signconf %s has errors", sc_str, scfile);
            signconf_cleanup(new_sc);
            return ODS_STATUS_CFG_ERR;
        }
        *signconf = new_sc;
    } else {
        ods_log_error("[%s] unable to read file %s: %s", sc_str, scfile,
            ods_status2str(status));
        signconf_cleanup(new_sc);
    }
    return status;
}


/**
 * Compare signer configurations.
 *
 */
task_id
signconf_compare(signconf_type* a, signconf_type* b, task_id default_task)
{
   task_id new_task = default_task;

   if (!a || !b) {
       return TASK_NONE;
   }
   ods_log_assert(a);
   ods_log_assert(b);

   if (a->nsec_type != b->nsec_type) {
       new_task = TASK_NSECIFY;
   } else if (a->nsec_type == LDNS_RR_TYPE_NSEC3) {
       if ((ods_strcmp(a->nsec3_salt, b->nsec3_salt) != 0) ||
           (a->nsec3_algo != b->nsec3_algo) ||
           (a->nsec3_iterations != b->nsec3_iterations) ||
           (a->nsec3_optout != b->nsec3_optout)) {

           new_task = TASK_NSECIFY;
       }
   }
   if (keylist_compare(a->keys, b->keys) != 0) {
       new_task = TASK_READ;
   }
   /* not like python: reschedule if resign/refresh differs */
   /* this needs review, tasks correct on signconf changes? */
   return new_task;
}


/**
 * Check the SOA/Serial type.
 *
 */
static int
signconf_soa_serial_check(const char* serial) {
    if (!serial) {
        return 1;
    }

    if (strlen(serial) == 4 && strncmp(serial, "keep", 4) == 0) {
        return 0;
    }
    if (strlen(serial) == 7 && strncmp(serial, "counter", 7) == 0) {
        return 0;
    }
    if (strlen(serial) == 8 && strncmp(serial, "unixtime", 8) == 0) {
        return 0;
    }
    if (strlen(serial) == 11 && strncmp(serial, "datecounter", 11) == 0) {
        return 0;
    }
    return 1;
}

/**
 * Check signer configuration settings.
 *
 */
ods_status
signconf_check(signconf_type* signconf)
{
    ods_status status = ODS_STATUS_OK;

    if (!signconf->sig_resign_interval) {
        ods_log_error("[%s] check failed: no signature resign interval found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->sig_refresh_interval) {
        ods_log_error("[%s] check failed: no signature resign interval found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->sig_validity_default) {
        ods_log_error("[%s] check failed: no signature default validity found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->sig_validity_denial) {
        ods_log_error("[%s] check failed: no signature denial validity found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->sig_jitter) {
        ods_log_error("[%s] check failed: no signature jitter found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->sig_inception_offset) {
        ods_log_error("[%s] check failed: no signature inception offset found",
            sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
        if (signconf->nsec3_algo == 0) {
            ods_log_error("[%s] check failed: no nsec3 algorithm found",
            sc_str);
            status = ODS_STATUS_CFG_ERR;
        }
        /* iterations */
        /* salt */
        /* optout */
    } else if (signconf->nsec_type != LDNS_RR_TYPE_NSEC) {
        ods_log_error("[%s] check failed: wrong nsec type %i", sc_str,
            signconf->nsec_type);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->keys || signconf->keys->count == 0) {
        ods_log_error("[%s] check failed: no keys found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->dnskey_ttl) {
        ods_log_error("[%s] check failed: no dnskey ttl found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->soa_ttl) {
        ods_log_error("[%s] check failed: no soa ttl found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->soa_min) {
        ods_log_error("[%s] check failed: no soa minimum found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    }
    if (!signconf->soa_serial) {
        ods_log_error("[%s] check failed: no soa serial type found", sc_str);
        status = ODS_STATUS_CFG_ERR;
    } else if (signconf_soa_serial_check(signconf->soa_serial) != 0) {
        ods_log_error("[%s] check failed: wrong soa serial type %s", sc_str,
            signconf->soa_serial);
        status = ODS_STATUS_CFG_ERR;
    }

    return status;
}


/**
 * Clean up signer configuration.
 *
 */
void
signconf_cleanup(signconf_type* signconf)
{
    allocator_type* allocator;

    if (!signconf) {
        return;
    }

    duration_cleanup(signconf->sig_resign_interval);
    duration_cleanup(signconf->sig_refresh_interval);
    duration_cleanup(signconf->sig_validity_default);
    duration_cleanup(signconf->sig_validity_denial);
    duration_cleanup(signconf->sig_jitter);
    duration_cleanup(signconf->sig_inception_offset);
    duration_cleanup(signconf->dnskey_ttl);
    duration_cleanup(signconf->soa_ttl);
    duration_cleanup(signconf->soa_min);

    allocator = signconf->allocator;
    allocator_deallocate(allocator);
    allocator_cleanup(allocator);
    return;
}


/**
 * Print sign configuration.
 *
 */
void
signconf_print(FILE* out, signconf_type* signconf, const char* name)
{
    char* s = NULL;

    fprintf(out, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");

    if (signconf) {
        fprintf(out, "<SignerConfiguration>\n");
        fprintf(out, "\t<Zone name=\"%s\">\n", name?name:"(null)");

        /* Signatures */
        fprintf(out, "\t\t<Signatures>\n");
        s = duration2string(signconf->sig_resign_interval);
        fprintf(out, "\t\t\t<Resign>%s</Resign>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(signconf->sig_refresh_interval);
        fprintf(out, "\t\t\t<Refresh>%s</Refresh>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t<Validity>\n");

        s = duration2string(signconf->sig_validity_default);
        fprintf(out, "\t\t\t\t<Default>%s</Default>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(signconf->sig_validity_denial);
        fprintf(out, "\t\t\t\t<Denial>%s</Denial>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t</Validity>\n");

        s = duration2string(signconf->sig_jitter);
        fprintf(out, "\t\t\t<Jitter>%s</Jitter>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(signconf->sig_inception_offset);
        fprintf(out, "\t\t\t<InceptionOffset>%s</InceptionOffset>\n",
            s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t</Signatures>\n");
        fprintf(out, "\n");

        /* Denial */
        fprintf(out, "\t\t<Denial>\n");
        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC) {
            fprintf(out, "\t\t\t<NSEC />\n");
        } else if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            fprintf(out, "\t\t\t<NSEC3>\n");
            if (signconf->nsec3_optout) {
                fprintf(out, "\t\t\t\t<OptOut />\n");
            }
            fprintf(out, "\t\t\t\t<Hash>\n");
            fprintf(out, "\t\t\t\t\t<Algorithm>%i</Algorithm>\n",
                signconf->nsec3_algo);
            fprintf(out, "\t\t\t\t\t<Iterations>%i</Iterations>\n",
                signconf->nsec3_iterations);
            fprintf(out, "\t\t\t\t\t<Salt>%s</Salt>\n",
                signconf->nsec3_salt?signconf->nsec3_salt:"(null)");
            fprintf(out, "\t\t\t\t</Hash>\n");
            fprintf(out, "\t\t\t</NSEC3>\n");
        }
        fprintf(out, "\t\t</Denial>\n");
        fprintf(out, "\n");

        /* Keys */
        fprintf(out, "\t\t<Keys>\n");
        s = duration2string(signconf->dnskey_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s?s:"(null)");
        free((void*)s);
        fprintf(out, "\n");
        keylist_print(out, signconf->keys);
        fprintf(out, "\t\t</Keys>\n");
        fprintf(out, "\n");

        /* SOA */
        fprintf(out, "\t\t<SOA>\n");
        s = duration2string(signconf->soa_ttl);
        fprintf(out, "\t\t\t<TTL>%s</TTL>\n", s?s:"(null)");
        free((void*)s);

        s = duration2string(signconf->soa_min);
        fprintf(out, "\t\t\t<Minimum>%s</Minimum>\n", s?s:"(null)");
        free((void*)s);

        fprintf(out, "\t\t\t<Serial>%s</Serial>\n",
            signconf->soa_serial?signconf->soa_serial:"(null)");
        fprintf(out, "\t\t</SOA>\n");
        fprintf(out, "\n");

        /* Audit */
        if (signconf->audit) {
            fprintf(out, "\t\t<Audit />\n");
            fprintf(out, "\n");
        }

        fprintf(out, "\t</Zone>\n");
        fprintf(out, "</SignerConfiguration>\n");
    }
    return;
}


/**
 * Log sign configuration.
 *
 */
void
signconf_log(signconf_type* signconf, const char* name)
{
    char* resign = NULL;
    char* refresh = NULL;
    char* validity = NULL;
    char* denial = NULL;
    char* jitter = NULL;
    char* offset = NULL;
    char* dnskeyttl = NULL;
    char* soattl = NULL;
    char* soamin = NULL;

    if (signconf) {
        resign = duration2string(signconf->sig_resign_interval);
        refresh = duration2string(signconf->sig_refresh_interval);
        validity = duration2string(signconf->sig_validity_default);
        denial = duration2string(signconf->sig_validity_denial);
        jitter = duration2string(signconf->sig_jitter);
        offset = duration2string(signconf->sig_inception_offset);
        dnskeyttl = duration2string(signconf->dnskey_ttl);
        soattl = duration2string(signconf->soa_ttl);
        soamin = duration2string(signconf->soa_min);

        ods_log_debug("[%s] zone %s signconf: RESIGN[%s] REFRESH[%s] "
            "VALIDITY[%s] DENIAL[%s] JITTER[%s] OFFSET[%s] NSEC[%i] "
            "DNSKEYTTL[%s] SOATTL[%s] MINIMUM[%s] SERIAL[%s] AUDIT[%i]",
            sc_str, name?name:"(null)", resign, refresh, validity, denial,
            jitter, offset, (int) signconf->nsec_type, dnskeyttl, soattl,
            soamin, signconf->soa_serial?signconf->soa_serial:"(null)",
            (int) signconf->audit);

        if (signconf->nsec_type == LDNS_RR_TYPE_NSEC3) {
            ods_log_debug("[%s] zone %s nsec3: OPTOUT[%i] ALGORITHM[%u] "
                "ITERATIONS[%u] SALT[%s]", sc_str, name,
                signconf->nsec3_optout, signconf->nsec3_algo,
                signconf->nsec3_iterations,
                signconf->nsec3_salt?signconf->nsec3_salt:"(null)");
        }

        /* Keys */
        keylist_log(signconf->keys, name);

        free((void*)resign);
        free((void*)refresh);
        free((void*)validity);
        free((void*)denial);
        free((void*)jitter);
        free((void*)offset);
        free((void*)dnskeyttl);
        free((void*)soattl);
        free((void*)soamin);
    }
    return;
}
