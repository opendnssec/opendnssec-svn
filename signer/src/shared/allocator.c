/*
 * $Id: allocator.c 3817 2010-08-27 08:43:00Z matthijs $
 *
 * Copyright (c) 2010-2011 NLNet Labs. All rights reserved.
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
 * Memory management.
 *
 */

#include "config.h"
#include "shared/allocator.h"
#include "shared/log.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/** Alignment */
#ifdef ALIGNMENT
#  undef ALIGNMENT
#endif
/** increase size until it fits alignment of s bytes */
#define ALIGN_UP(x, s) (((x) + s - 1) & (~(s - 1)))
/** what size to align on; make sure a char* fits in it. */
#define ALIGNMENT (sizeof(uint64_t))

/** Default reasonable size for chunks and objects */
#define ALLOCATOR_CHUNK_SIZE 8192
#define ALLOCATOR_LARGE_OBJECT_SIZE 2048

static const char* allocator_str = "allocator";


/**
 * Create allocator.
 *
 */
allocator_type*
allocator_create(void *(*allocator)(size_t size), void (*deallocator)(void *))
{
    return allocator_create_custom(allocator, deallocator, ALLOCATOR_CHUNK_SIZE);
}


/**
 * Initialize allocator.
 *
 */
/*
static void
allocator_init(allocator_type* allocator)
{
    size_t a = 0;
    ods_log_debug("[%s] initialize allocator", allocator_str);
    if (!allocator) {
        return;
    }
    ods_log_debug("[%s] align up allocator", allocator_str);
    a = ALIGN_UP(sizeof(allocator_type), ALIGNMENT);
    allocator->chunk = (char*) allocator + a;
    allocator->next = NULL;
    allocator->large_list = NULL;
    allocator->available = allocator->first_size - a;
    allocator->total_large = 0;
    return;
}
*/

/**
 * Create allocator.
 *
 */
allocator_type* allocator_create_custom(void *(*allocator)(size_t size),
    void (*deallocator)(void *), size_t size)
{
    allocator_type* result =
        (allocator_type*) allocator(sizeof(allocator_type));
/*     ods_log_assert(sizeof(allocator_type) <= size); */
    if (!result) {
        ods_log_error("[%s] failed to create allocator", allocator_str);
        return NULL;
    }
    result->allocator = allocator;
    result->deallocator = deallocator;
/*
    result->first_size = size;
    allocator_init(result);
*/
    return result;
}


/**
 * Allocate memory.
 *
 */
void*
allocator_alloc(allocator_type* allocator, size_t size)
{
    size_t a = ALIGN_UP(size, ALIGNMENT);
    void* result;
    ods_log_assert(allocator);
    result = allocator->allocator(size);
    if (!result) {
        ods_fatal_exit("[%s] allocator failed: out of memory", allocator_str);
        return NULL;
    }
    return result;

    /* large objects */
/*
    if (a > ALLOCATOR_LARGE_OBJECT_SIZE) {
         result = allocator->allocator(ALIGNMENT + size);
         if (!result) {
            ods_fatal_exit("[%s] allocator failed: out of memory",
                allocator_str);
            return NULL;
         }
         allocator->total_large += ALIGNMENT + size;
         *(char**)result = allocator->large_list;
         allocator->large_list = (char*)result;
         return (char*)result + ALIGNMENT;
    }
*/
    /* new chunk */
/*
    if (a > allocator->available) {
        result = allocator->allocator(ALLOCATOR_CHUNK_SIZE);
         if (!result) {
            ods_fatal_exit("[%s] allocator failed: out of memory",
                allocator_str);
            return NULL;
         }
         *(char**) result = allocator->next;
         allocator->next = (char*) result;
         allocator->chunk = (char*) result + ALIGNMENT;
         allocator->available = ALLOCATOR_CHUNK_SIZE - ALIGNMENT;
    }
    allocator->available -= a;
    result = allocator->chunk;
    allocator->chunk += a;
    return result;
*/
}


/**
 * Allocate memory and initialize to zero.
 *
 */
void*
allocator_alloc_zero(allocator_type *allocator, size_t size)
{
    void *result = allocator_alloc(allocator, size);
    if (!result) {
        return NULL;
    }
    memset(result, 0, size);
    return result;
}


/**
 * Allocate memory and initialize with data.
 *
 */
void*
allocator_alloc_init(allocator_type *allocator, size_t size, const void *init)
{
    void *result = allocator_alloc(allocator, size);
    if (!result) {
        return NULL;
    }
    memcpy(result, init, size);
    return result;
}


/**
 * Duplicate string.
 *
 */
char*
allocator_strdup(allocator_type *allocator, const char *string)
{
    if (!string) {
        return NULL;
    }
    return (char*) allocator_alloc_init(allocator, strlen(string) + 1, string);
}


/**
 * Deallocate memory.
 *
 */
void
allocator_deallocate(allocator_type *allocator, void* data)
{
    ods_log_assert(allocator);
    if (!data) {
        return;
    }
    allocator->deallocator(data);
    return;
}


/**
 * Free all data in allocator.
 *
 */
void
allocator_free(allocator_type* allocator)
{
/*
    char* chunk = NULL;
    char* next_chunk = NULL;
    void (*deallocator)(void *);
    if (!allocator) {
        return;
    }
    chunk = allocator->next;
    deallocator = allocator->deallocator;
    while (chunk) {
        next_chunk = *(char**)chunk;
        deallocator(chunk);
        chunk = next_chunk;
    }
    chunk = allocator->large_list;
    while (chunk) {
        next_chunk = *(char**)chunk;
        deallocator(chunk);
        chunk = next_chunk;
    }
    allocator_init(allocator);
*/
    return;
}


/**
 * Cleanup allocator.
 *
 */
void
allocator_cleanup(allocator_type *allocator)
{
    void (*deallocator)(void *);
    if (!allocator) {
        return;
    }
/*    allocator_free(allocator); */
    deallocator = allocator->deallocator;
    deallocator(allocator);
    return;
}

