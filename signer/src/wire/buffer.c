/*
 * $Id: buffer.c 4958 2011-04-18 07:11:09Z matthijs $
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
 * Packet buffer.
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 23 |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 45 |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 67 |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 89 |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * 01 |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */


#include "config.h"
#include "shared/log.h"
#include "wire/buffer.h"

#include <string.h>

/**
 * Create a new buffer with the specified capacity.
 *
 */
buffer_type*
buffer_create(allocator_type* allocator, size_t capacity)
{
    buffer_type* buffer = NULL;
    if (!allocator || !capacity) {
        return NULL;
    }
    buffer = (buffer_type *) allocator_alloc(allocator, sizeof(buffer_type));
    if (!buffer) {
        return NULL;
    }
    buffer->data = (uint8_t*) calloc(capacity, sizeof(uint8_t));
    buffer->position = 0;
    buffer->limit = capacity;
    buffer->capacity = capacity;
    buffer->fixed = 0;
    return buffer;
}


/**
 * Create a buffer with the specified data.
 *
 */
void
buffer_create_from(buffer_type* buffer, void* data, size_t size)
{
    ods_log_assert(buffer);
    buffer->data = (uint8_t*) data;
    buffer->position = 0;
    buffer->limit = size;
    buffer->capacity = size;
    buffer->fixed = 1;
    return;
}


/**
 * Clear the buffer and make it ready for writing.
 *
 */
void
buffer_clear(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    buffer->limit = buffer->capacity;
    return;
}


/**
 * Flip the buffer and make it ready for reading.
 *
 */
void
buffer_flip(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->limit = buffer->position;
    buffer->position = 0;
    return;
}


/**
 * Make the buffer ready for re-reading the data.
 *
 */
void
buffer_rewind(buffer_type* buffer)
{
    ods_log_assert(buffer);
    buffer->position = 0;
    return;
}


/**
 * Get the buffer's position.
 *
 */
size_t
buffer_position(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->position;
}


/**
 * Set the buffer's position.
 *
 */
void
buffer_set_position(buffer_type* buffer, size_t pos)
{
    ods_log_assert(buffer);
    ods_log_assert(pos <= buffer->limit);
    buffer->position = pos;
    return;
}


/**
 * Change the buffer's position.
 *
 */
void
buffer_skip(buffer_type* buffer, ssize_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer->position + count <= buffer->limit);
    buffer->position += count;
    return;
}


/**
 * Change the buffer's position so that one dname is skipped.
 *
 */
int
buffer_skip_dname(buffer_type* buffer)
{
    ods_log_assert(buffer);
    while (1) {
        uint8_t label_size = 0;
        if (!buffer_available(buffer, 1)) {
            return 0;
        }
        label_size = buffer_read_u8(buffer);
        if (label_size == 0) {
            break;
        } else if ((label_size & 0xc0) != 0) {
            if (!buffer_available(buffer, 1)) {
                return 0;
            }
            buffer_skip(buffer, 1);
            break;
        } else if (!buffer_available(buffer, label_size)) {
            return 0;
        } else {
            buffer_skip(buffer, label_size);
        }
    }
    return 1;
}


/**
 * Change the buffer's position so that one RR is skipped.
 *
 */
int
buffer_skip_rr(buffer_type* buffer, unsigned qrr)
{
    if (!buffer_skip_dname(buffer)) {
        return 0;
    }
    if (qrr) {
        if (!buffer_available(buffer, 4)) {
            return 0;
        }
        buffer_skip(buffer, 4);
    } else {
        uint16_t rdata_size;
        if (!buffer_available(buffer, 10)) {
            return 0;
        }
        buffer_skip(buffer, 8);
        rdata_size = buffer_read_u16(buffer);
        if (!buffer_available(buffer, rdata_size)) {
            return 0;
        }
        buffer_skip(buffer, rdata_size);
    }
    return 1;
}


/**
 * Get the buffer's limit.
 *
 */
size_t
buffer_limit(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->limit;
}


/**
 * Set the buffer's limit.
 *
 */
void
buffer_set_limit(buffer_type* buffer, size_t limit)
{
    ods_log_assert(buffer);
    ods_log_assert(limit <= buffer->capacity);
    buffer->limit = limit;
    if (buffer->position > buffer->limit) {
        buffer->position = buffer->limit;
    }
    return;
}


/**
 * Get the buffer's capacity.
 *
 */
size_t
buffer_capacity(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer->capacity;
}


/**
 * Return a pointer to the data at the indicated position.
 *
 */
uint8_t*
buffer_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->data + at;
}


/**
 * Return a pointer to the data at the beginning of the buffer.
 *
 */
uint8_t*
buffer_begin(buffer_type* buffer)
{
    return buffer_at(buffer, 0);
}


/**
 * Return a pointer to the data at the end of the buffer.
 *
 */
uint8_t*
buffer_end(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->limit);
}


/**
 * Return a pointer to the data at the buffer's current position.
 *
 */
uint8_t*
buffer_current(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_at(buffer, buffer->position);
}


/**
 * The number of bytes remaining between the at and limit.
 *
 */
static size_t
buffer_remaining_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at <= buffer->limit);
    return buffer->limit - at;
}

/**
 * The number of bytes remaining between the buffer's position and limit.
 *
 */
size_t
buffer_remaining(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_remaining_at(buffer, buffer->position);
}


/**
 * Check if the buffer has enough bytes available.
 *
 */
int
buffer_available(buffer_type* buffer, size_t count)
{
    ods_log_assert(buffer);
    return count <= buffer_remaining_at(buffer, buffer->position);
}


/**
 * Write to buffer at indicated position.
 *
 */
static void
buffer_write_u16_at(buffer_type* buffer, size_t at, uint16_t data)
{
    ods_log_assert(buffer);
    write_uint16(buffer->data + at, data);
    return;
}


/**
 * Write to buffer.
 *
 */
void
buffer_write(buffer_type* buffer, const void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(buffer->data + buffer->position, data, count);
    buffer->position += count;
    return;
}


/**
 * Write uint16_t to buffer.
 *
 */
void
buffer_write_u16(buffer_type* buffer, uint16_t data)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, buffer->position, data);
    buffer->position += sizeof(data);
    return;
}


/**
 * Write rdf to buffer.
 *
 */
void
buffer_write_rdf(buffer_type* buffer, ldns_rdf* rdf)
{
    ods_log_assert(rdf);
    buffer_write(buffer, ldns_rdf_data(rdf), ldns_rdf_size(rdf));
    /* position updated by buffer_write() */
    return;
}


/**
 * Write rr to buffer.
 *
 */
void
buffer_write_rr(buffer_type* buffer, ldns_rr* rr)
{
    size_t i = 0;
    ods_log_assert(rr);
    buffer_write_rdf(buffer, ldns_rr_owner(rr));
    buffer_write_u16(buffer, (uint16_t) ldns_rr_get_type(rr));
    buffer_write_u16(buffer, (uint16_t) ldns_rr_get_class(rr));
    for (i=0; i < ldns_rr_rd_count(rr); i++) {
        buffer_write_rdf(buffer, ldns_rr_rdf(rr, i));
    }
    /* position updated by buffer_write() */
    return;
}


/**
 * Read uint8_t from buffer at indicated position.
 *
 */
static uint8_t
buffer_read_u8_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    ods_log_assert(at < buffer->capacity);
    return buffer->data[at];

}


/**
 * Read uint16_t from buffer at indicated position.
 *
 */
static uint16_t
buffer_read_u16_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint16(buffer->data + at);
}


/**
 * Read uint32_t from buffer at indicated position.
 *
 */
static uint32_t
buffer_read_u32_at(buffer_type* buffer, size_t at)
{
    ods_log_assert(buffer);
    return read_uint32(buffer->data + at);
}


/**
 * Read from buffer.
 *
 */
void
buffer_read(buffer_type* buffer, void* data, size_t count)
{
    ods_log_assert(buffer);
    ods_log_assert(buffer_available(buffer, count));
    memcpy(data, buffer->data + buffer->position, count);
    buffer->position += count;
    return;
}


/**
 * Read uint8_t from buffer.
 *
 */
uint8_t
buffer_read_u8(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u8_at(buffer, buffer->position);
    buffer->position += sizeof(uint8_t);
    return result;
}


/**
 * Read uint16_t from buffer.
 *
 */
uint16_t
buffer_read_u16(buffer_type* buffer)
{
    uint16_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u16_at(buffer, buffer->position);
    buffer->position += sizeof(uint16_t);
    return result;
}


/**
 * Read uint32_t from buffer.
 *
 */
uint32_t
buffer_read_u32(buffer_type* buffer)
{
    uint32_t result = 0;
    ods_log_assert(buffer);
    result = buffer_read_u32_at(buffer, buffer->position);
    buffer->position += sizeof(uint32_t);
    return result;
}


/**
 * Get query id from buffer.
 *
 */
uint16_t
buffer_pkt_id(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 0);
}

/**
 * Get a random query id.
 *
 */
static uint16_t
random_id(void)
{
    return (uint16_t) 4; /* could be more random */
}

/**
 * Set random query id in buffer.
 *
 */
void
buffer_pkt_set_random_id(buffer_type* buffer)
{
    uint16_t qid = 0;
    ods_log_assert(buffer);
    qid = random_id();
    buffer_write_u16_at(buffer, 0, qid);
    return;
}


/**
 * Get flags from buffer.
 *
 */
uint16_t
buffer_pkt_flags(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (uint16_t) buffer_read_u16_at(buffer, 2);
}


/**
 * Set flags in buffer.
 *
 */
void
buffer_pkt_set_flags(buffer_type* buffer, uint16_t flags)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 2, flags);
    return;
}


/**
 * Get QR bit from buffer.
 *
 */
int
buffer_pkt_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) QR(buffer);
}


/**
 * Set QR bit in buffer.
 *
 */
void
buffer_pkt_set_qr(buffer_type* buffer)
{
    ods_log_assert(buffer);
    QR_SET(buffer);
    return;
}


/**
 * Get OPCODE from buffer.
 *
 */
ldns_pkt_opcode
buffer_pkt_opcode(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (ldns_pkt_opcode) OPCODE(buffer);
}


/**
 * Set OPCODE in buffer.
 *
 */
void
buffer_pkt_set_opcode(buffer_type* buffer, ldns_pkt_opcode opcode)
{
    ods_log_assert(buffer);
    OPCODE_SET(buffer, opcode);
    return;
}


/**
 * Get AA bit from buffer.
 *
 */
int
buffer_pkt_aa(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AA(buffer);
}


/**
 * Get TC bit from buffer.
 *
 */
int
buffer_pkt_tc(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) TC(buffer);
}


/**
 * Get RD bit from buffer.
 *
 */
int
buffer_pkt_rd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RD(buffer);
}


/**
 * Get RA bit from buffer.
 *
 */
int
buffer_pkt_ra(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) RA(buffer);
}


/**
 * Get AD bit from buffer.
 *
 */
int
buffer_pkt_ad(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) AD(buffer);
}


/**
 * Get CD bit from buffer.
 *
 */
int
buffer_pkt_cd(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (int) CD(buffer);
}


/**
 * Get RCODE from buffer.
 *
 */
ldns_pkt_rcode
buffer_pkt_rcode(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return (ldns_pkt_rcode) RCODE(buffer);
}


/**
 * Set RCODE in buffer.
 *
 */
void
buffer_pkt_set_rcode(buffer_type* buffer, ldns_pkt_rcode rcode)
{
    ods_log_assert(buffer);
    RCODE_SET(buffer, rcode);
    return;
}


/**
 * Get QDCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_qdcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 4);
}


/**
 * Set QDCOUNT in buffer.
 *
 */
void
buffer_pkt_set_qdcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 4, count);
    return;
}


/**
 * Get ANCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_ancount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 6);
}


/**
 * Set ANCOUNT in buffer.
 *
 */
void
buffer_pkt_set_ancount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 6, count);
    return;
}


/**
 * Get NSCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_nscount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 6);
}


/**
 * Set NSCOUNT in buffer.
 *
 */
void
buffer_pkt_set_nscount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 6, count);
    return;
}


/**
 * Get ARCOUNT from buffer.
 *
 */
uint16_t
buffer_pkt_arcount(buffer_type* buffer)
{
    ods_log_assert(buffer);
    return buffer_read_u16_at(buffer, 8);
}


/**
 * Set ARCOUNT in buffer.
 *
 */
void
buffer_pkt_set_arcount(buffer_type* buffer, uint16_t count)
{
    ods_log_assert(buffer);
    buffer_write_u16_at(buffer, 8, count);
    return;
}


/**
 * Make a new packet.
 *
 */
static void
buffer_pkt_new(buffer_type* buffer, ldns_rdf* qname, ldns_rr_type qtype,
   ldns_rr_class qclass, ldns_pkt_opcode opcode)
{
    ods_log_assert(buffer);
    ods_log_assert(qname);
    ods_log_assert(qtype);
    ods_log_assert(qclass);
    /* The header */
    buffer_clear(buffer);
    buffer_pkt_set_random_id(buffer);
    buffer_pkt_set_opcode(buffer, opcode);
    buffer_pkt_set_qdcount(buffer, 1);
    buffer_pkt_set_ancount(buffer, 0);
    buffer_pkt_set_nscount(buffer, 0);
    buffer_pkt_set_arcount(buffer, 0);
    buffer_skip(buffer, BUFFER_PKT_HEADER_SIZE);
    /* The question record */
    buffer_write_rdf(buffer, qname);
    buffer_write_u16(buffer, qtype);
    buffer_write_u16(buffer, qclass);
    return;
}


/**
 * Make a new query.
 *
 */
void
buffer_pkt_query(buffer_type* buffer, ldns_rdf* qname, ldns_rr_type qtype,
   ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, qtype, qclass, LDNS_PACKET_QUERY);
    buffer_pkt_set_flags(buffer, 0);
    return;
}


/**
 * Make a new notify.
 *
 */
void
buffer_pkt_notify(buffer_type* buffer, ldns_rdf* qname, ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, LDNS_RR_TYPE_SOA, qclass,
        LDNS_PACKET_NOTIFY);
    return;
}


/**
 * Make a new axfr.
 *
 */
void
buffer_pkt_axfr(buffer_type* buffer, ldns_rdf* qname, ldns_rr_class qclass)
{
    buffer_pkt_new(buffer, qname, LDNS_RR_TYPE_AXFR, qclass,
        LDNS_PACKET_QUERY);
    buffer_pkt_set_qr(buffer);
    return;
}


/**
 * Print packet buffer.
 *
 */
void
buffer_pkt_print(FILE* fd, buffer_type* buffer)
{
    ldns_pkt* pkt = NULL;
    ods_log_assert(fd);
    ods_log_assert(buffer);
    if (ldns_wire2pkt(&pkt, buffer_begin(buffer), buffer_limit(buffer)) ==
        LDNS_STATUS_OK) {
        ods_log_assert(pkt);
        ldns_pkt_print(fd, pkt);
        ldns_pkt_free(pkt);
    } else {
        fprintf(fd, ";;\n");
        fprintf(fd, ";; Bogus packet\n");
        fprintf(fd, ";;\n");
        fprintf(fd, ";;\n");
        fprintf(fd, "\n");
    }
    return;
}


/**
 * Clean up buffer.
 *
 */
void
buffer_cleanup(buffer_type* buffer, allocator_type* allocator)
{
    if (!buffer || !allocator) {
        return;
    }
    free((void*)buffer->data);
    allocator_deallocate(allocator, (void*) buffer);
    return;
}


