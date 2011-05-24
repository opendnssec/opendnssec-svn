/*
 * $Id: journal.h 4644 2011-03-24 14:22:54Z matthijs $
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

#ifndef SIGNER_JOURNAL_H
#define SIGNER_JOURNAL_H

#include "config.h"
#include "shared/allocator.h"
#include "shared/locks.h"
#include "shared/status.h"

#include <ldns/ldns.h>

#define MAX_TRANSACTIONS 5

/**
 * Transaction structure.
 *
 */
typedef struct transaction_struct transaction_type;
struct transaction_struct {
    allocator_type* allocator;
    /* time of transaction */
    /* size of transaction */
    uint32_t serial_from;
    uint32_t serial_to;
    ldns_dnssec_rrs* add;
    ldns_dnssec_rrs* remove;
    transaction_type* next;
};

/**
 * Journal structure.
 *
 */
typedef struct journal_struct journal_type;
struct journal_struct {
    allocator_type* allocator;
    transaction_type* transactions;
    lock_basic_type journal_lock;
};

/**
 * Create transaction.
 * \param[in] allocator memory allocator
 * \return the created transaction
 *
 */
transaction_type* transaction_create(allocator_type* allocator);

/**
 * Add RR addition to transaction.
 * \param[in] transaction the transaction
 * \param[in] rr the RR to be added.
 * \return ods_status status
 *
 */
ods_status transaction_add_rr(transaction_type* transaction, ldns_rr* rr);

/**
 * Add RR removal to transaction.
 * \param[in] transaction the transaction
 * \param[in] rr the RR to be added.
 * \return ods_status status
 *
 */
ods_status transaction_del_rr(transaction_type* transaction, ldns_rr* rr);

/**
 * Print transaction.
 * \param[in] fd file descriptor
 * \param[in] transaction the transaction
 *
 */
void transaction_print(FILE* fd, transaction_type* transaction);

/**
 * Clean up transaction.
 * \param[in] transaction the transaction
 *
 */
void transaction_cleanup(transaction_type* transaction);

/**
 * Create journal.
 * \param[in] allocator memory allocator
 * \return the created journal
 *
 */
journal_type* journal_create(allocator_type* allocator);

/**
 * Lookup transaction in journal.
 * \param[in] journal the journal
 * \param[in] serial_from from serial
 * \return transaction_type* transaction, if found
 *
 */
transaction_type* journal_lookup_transaction(journal_type* journal,
    uint32_t serial_from);

/**
 * Add transaction to journal.
 * \param[in] journal the journal
 * \param[in] transaction the transaction
 * \return ods_status status
 *
 */
ods_status journal_add_transaction(journal_type* journal,
    transaction_type* transaction);

/**
 * Add RR addition to first transaction in journal.
 * \param[in] journal the journal
 * \param[in] rr the RR to be added.
 * \return ods_status status
 *
 */
ods_status journal_add_rr(journal_type* journal, ldns_rr* rr);

/**
 * Add RR removal to first transaction in journal.
 * \param[in] journal the journal
 * \param[in] rr the RR to be added.
 * \return ods_status status
 *
 */
ods_status journal_del_rr(journal_type* journal, ldns_rr* rr);

/**
 * Purge journal.
 * \param[in] journal journal to be deleted
 * \param[in] number of transactions to keep
 * \return ods_status status
 *
 */
ods_status journal_purge(journal_type* journal, size_t num);

/**
 * Print journal.
 * \param[in] fd file descriptor
 * \param[in] journal the journal
 *
 */
void journal_print(FILE* fd, journal_type* journal);

/**
 * Clean up journal.
 * \param[in] journal journal to be deleted
 *
 */
void journal_cleanup(journal_type* journal);

#endif /* SIGNER_JOURNAL_H */
