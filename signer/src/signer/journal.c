/*
 * $Id: journal.c 4644 2011-03-24 14:22:54Z matthijs $
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
 * Zone journal for IXFR serving.
 *
 */

#include "config.h"
#include "shared/allocator.h"
#include "shared/log.h"
#include "signer/journal.h"

#include <stdio.h>

static const char* journal_str = "journal";


/**
 * Create transaction.
 *
 */
transaction_type*
transaction_create(allocator_type* allocator)
{
    transaction_type* transaction;

    if (!allocator) {
        return NULL;
    }
    ods_log_assert(allocator);

    transaction = (transaction_type*) allocator_alloc(allocator,
        sizeof(transaction_type));
    if (!transaction) {
        return NULL;
    }
    transaction->allocator = allocator;

    transaction->serial_from = 0;
    transaction->serial_to = 0;
    transaction->next = NULL;

    transaction->add = ldns_dnssec_rrs_new();
    if (!transaction->add) {
        transaction_cleanup(transaction);
        return NULL;
    }
    transaction->remove = ldns_dnssec_rrs_new();
    if (!transaction->remove) {
        transaction_cleanup(transaction);
        return NULL;
    }
    return transaction;
}


/**
 * Add RR addition to transaction.
 *
 */
ods_status
transaction_add_rr(transaction_type* transaction, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!transaction || !rr) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(transaction->add);

    status = ldns_dnssec_rrs_add_rr(transaction->add, rr);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to add +RR to transaction: %s",
            journal_str, ldns_get_errorstr_by_id(status));
        return ODS_STATUS_ERR;
    }
    return ODS_STATUS_OK;
}


/**
 * Add RR removal to transaction.
 *
 */
ods_status
transaction_del_rr(transaction_type* transaction, ldns_rr* rr)
{
    ldns_status status = LDNS_STATUS_OK;

    if (!transaction || !rr) {
        return ODS_STATUS_ASSERT_ERR;
    }
    ods_log_assert(transaction->remove);

    status = ldns_dnssec_rrs_add_rr(transaction->remove, rr);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to add -RR to transaction: %s",
            journal_str, ldns_get_errorstr_by_id(status));
        return ODS_STATUS_ERR;
    }
    return ODS_STATUS_OK;
}


/**
 * Print transaction.
 *
 */
void
transaction_print(FILE* fd, transaction_type* transaction)
{
    if (!fd || !transaction) {
        return;
    }
    fprintf(fd, ";;IXFR from %u to %u\n", transaction->serial_from,
        transaction->serial_to);

    /* print first soa */
    /* print from soa */
    if (transaction->remove) {
        ldns_dnssec_rrs_print(fd, transaction->remove);
    }
    /* print to soa */
    if (transaction->add) {
        ldns_dnssec_rrs_print(fd, transaction->add);
    }
    /* print final soa */

    fprintf(fd, ";;\n");
    return;
}



/**
 * Clean up transaction.
 *
 */
void
transaction_cleanup(transaction_type* transaction)
{
    allocator_type* allocator;

    if (!transaction) {
        return;
    }
    transaction_cleanup(transaction->next);

    allocator = transaction->allocator;
    if (transaction->add) {
        ldns_dnssec_rrs_deep_free(transaction->add);
        transaction->add = NULL;
    }
    if (transaction->remove) {
        ldns_dnssec_rrs_deep_free(transaction->remove);
        transaction->remove = NULL;
    }
    allocator_deallocate(allocator, (void*) transaction);
    return;
}


/**
 * Create journal.
 *
 */
journal_type*
journal_create(allocator_type* allocator)
{
    journal_type* journal;

    if (!allocator) {
        return NULL;
    }
    ods_log_assert(allocator);

    journal = (journal_type*) allocator_alloc(allocator,
        sizeof(journal_type));
    if (!journal) {
        return NULL;
    }
    journal->allocator = allocator;
    journal->transactions = NULL;
    lock_basic_init(&journal->journal_lock);
    return journal;
}


/**
 * Add transaction to journal.
 *
 */
ods_status
journal_add_transaction(journal_type* journal, transaction_type* transaction)
{
    if (!journal || !transaction) {
        return ODS_STATUS_ASSERT_ERR;
    }

    transaction->next = journal->transactions;
    journal->transactions = transaction;
    return ODS_STATUS_OK;
}


/**
 * Purge journal.
 *
 */
ods_status
journal_purge(journal_type* journal)
{
    /* no purging strategy for now */
    return ODS_STATUS_OK;
}


/**
 * Clean up journal.
 *
 */
void
journal_cleanup(journal_type* journal)
{
    allocator_type* allocator;
    lock_basic_type journal_lock;

    if (!journal) {
        return;
    }
    allocator = journal->allocator;
    journal_lock = journal->journal_lock;

    if (journal->transactions) {
        transaction_cleanup(journal->transactions);
        journal->transactions = NULL;
    }

    allocator_deallocate(allocator, (void*) journal);
    lock_basic_destroy(&journal_lock);
    return;
}
