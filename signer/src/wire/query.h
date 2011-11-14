/*
 * $Id: query.h 4958 2011-04-18 07:11:09Z matthijs $
 *
 * Copyright (c) 2011 NLNet Labs. All rights reserved.
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
 * Query.
 *
 */

#ifndef WIRE_QUERY_H
#define WIRE_QUERY_H

#include "config.h"
#include "shared/allocator.h"
#include "signer/zone.h"
#include "wire/buffer.h"

#define UDP_MAX_MESSAGE_LEN 512
#define TCP_MAX_MESSAGE_LEN 65535

enum query_enum {
        QUERY_PROCESSED = 0,
        QUERY_DISCARDED,
        QUERY_AXFR
};
typedef enum query_enum query_state;

/**
 * Query.
 *
 */
typedef struct query_struct query_type;
struct query_struct {
    /* Memory allocaotr */
    allocator_type* allocator;
    /* Query from addres */
    struct sockaddr_storage addr;
    socklen_t addrlen;
    /* Maximum supported query size */
    size_t maxlen;
    size_t reserved_space;
    /* TSIG */
    /* TCP */
    int tcp;
    uint16_t tcplen;
    buffer_type* buffer;
    /* QNAME, QTYPE, QCLASS */
    /* Zone */
    zone_type* zone;
    /* Compression */

    /* AXFR */
    int axfr_is_done;
    FILE* axfr_fd;
};

/**
 * Create query.
 * \return query_type* query
 *
 */
query_type* query_create(void);

/**
 * Process query.
 * \param[in] q query
 * \param[in] engine signer engine
 * \return query_state state of the query
 *
 */
query_state query_process(query_type* q, void* engine);

/**
 * Reset query.
 * \param[in] q query
 * \param[in] maxlen maximum message length
 * \param[in] is_tcp 1 if tcp query
 *
 */
void query_reset(query_type* q, size_t maxlen, int is_tcp);

/**
 * Cleanup query.
 * \param[in] q query
 *
 */
void query_cleanup(query_type* q);

#endif /* WIRE_QUERY_H */
