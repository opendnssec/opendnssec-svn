/*
 * $Id: acl.h 4958 2011-04-18 07:11:09Z matthijs $
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
 * Access Control List.
 *
 */

#include "config.h"
#include "shared/log.h"
#include "shared/status.h"
#include "wire/acl.h"

static const char* acl_str = "acl";


/**
 * Returns range type.
 * mask is the 2nd part of the range.
 *
 */
static acl_range_type
acl_parse_range_type(char* ip, char** mask)
{
    char *p;
    if((p=strchr(ip, '&'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_MASK;
    }
    if((p=strchr(ip, '/'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_SUBNET;
    }
    if((p=strchr(ip, '-'))!=0) {
        *p = 0;
        *mask = p+1;
        return ACL_RANGE_MINMAX;
    }
    *mask = 0;
    return ACL_RANGE_SINGLE;
}


/**
 * Parses subnet mask, fills 0 mask as well
 *
 */
static ods_status
acl_parse_range_subnet(char* p, void* addr, int maxbits)
{
    int subnet_bits = atoi(p);
    uint8_t* addr_bytes = (uint8_t*)addr;
    if (subnet_bits == 0 && strcmp(p, "0")!=0) {
        return ODS_STATUS_ACL_SUBNET_BAD_RANGE;
    }
    if (subnet_bits < 0 || subnet_bits > maxbits) {
        return ODS_STATUS_ACL_SUBNET_OUT_RANGE;
    }
    /* fill addr with n bits of 1s (struct has been zeroed) */
    while(subnet_bits >= 8) {
        *addr_bytes++ = 0xff;
        subnet_bits -= 8;
    }
    if(subnet_bits > 0) {
        uint8_t shifts[] =
            {0x0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
        *addr_bytes = shifts[subnet_bits];
    }
    return ODS_STATUS_OK;
}


/**
 * Create ACL.
 *
 */
acl_type*
acl_create(allocator_type* allocator, char* ipv4, char* ipv6, char* port,
    char* tsig_name)
{
    ods_status status = ODS_STATUS_OK;
    acl_type* acl = NULL;
    char* a = NULL;
    char* p = NULL;
    if (!allocator) {
        return NULL;
    }
    if (!ipv4 && !ipv6) {
        return NULL;
    }
    acl = (acl_type*) allocator_alloc(allocator, sizeof(acl_type));
    if (!acl) {
        ods_log_error("[%s] unable to create acl: allocator_alloc() "
            "failed", acl_str);
        return NULL;
    }
    acl->next = NULL;
    acl->tsig = NULL;
    acl->tsig_name = tsig_name;
    acl->port = 0;
    if (port) {
        acl->port = atoi((const char*) port);
    }
    if (ipv4) {
        a = ipv4;
        acl->family = AF_INET;
    } else if (ipv6) {
        a = ipv6;
        acl->family = AF_INET6;
    }
    memset(&acl->addr, 0, sizeof(union acl_addr_storage));
    memset(&acl->range_mask, 0, sizeof(union acl_addr_storage));

    acl->range_type = acl_parse_range_type(a, &p);
    acl->address = allocator_strdup(allocator, a);
    if (!acl->address) {
        ods_log_error("[%s] unable to create acl: allocator_strdup() failed",
            acl_str);
        acl_cleanup(acl, allocator);
        return NULL;
    }
    if (acl->family == AF_INET6) {
        if (inet_pton(AF_INET6, acl->address, &acl->addr.addr6) != 1) {
            ods_log_error("[%s] unable to create acl: bad ipv6 address (%s)",
                acl_str, acl->address);
            acl_cleanup(acl, allocator);
            return NULL;
        }
        if (acl->range_type == ACL_RANGE_MASK ||
            acl->range_type == ACL_RANGE_MINMAX) {
            if (inet_pton(AF_INET6, p, &acl->range_mask.addr6) != 1) {
                ods_log_error("[%s] unable to create acl: bad ipv6 address "
                    "mask (%s)", acl_str, p);
                acl_cleanup(acl, allocator);
                return NULL;
            }
        } else if (acl->range_type == ACL_RANGE_SUBNET) {
            status = acl_parse_range_subnet(p, &acl->range_mask.addr6, 128);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to create acl: %s (%s)",
                    acl_str, ods_status2str(status), p);
                acl_cleanup(acl, allocator);
                return NULL;
            }
        }
    } else if (acl->family == AF_INET) {
        if (inet_pton(AF_INET, acl->address, &acl->addr.addr) != 1) {
            ods_log_error("[%s] unable to create acl: bad ipv4 address (%s)",
                acl_str, acl->address);
            acl_cleanup(acl, allocator);
            return NULL;
        }
        if (acl->range_type == ACL_RANGE_MASK ||
            acl->range_type == ACL_RANGE_MINMAX) {
            if (inet_pton(AF_INET, p, &acl->range_mask.addr) != 1) {
                ods_log_error("[%s] unable to create acl: bad ipv6 address "
                    "mask (%s)", acl_str, p);
                acl_cleanup(acl, allocator);
                return NULL;
            }
        } else if (acl->range_type == ACL_RANGE_SUBNET) {
            status = acl_parse_range_subnet(p, &acl->range_mask.addr, 32);
            if (status != ODS_STATUS_OK) {
                ods_log_error("[%s] unable to create acl: %s (%s)",
                    acl_str, ods_status2str(status), p);
                acl_cleanup(acl, allocator);
                return NULL;
            }
        }
    }
    acl->ixfr_disabled = 0;
    /* tsig */
    /* TODO */
    return acl;
}


/**
 * ACL matches address mask.
 *
 */
static int
acl_addr_matches_mask(uint32_t* a, uint32_t* b, uint32_t* mask, size_t sz)
{
    size_t i = 0;
    ods_log_assert(sz % 4 == 0);
    sz /= 4;
    for (i=0; i<sz; ++i) {
        if (((*a++)&*mask) != ((*b++)&*mask)) {
            return 0;
        }
        ++mask;
    }
    return 1;
}

/**
 * ACL matches address range.
 *
 */
static int
acl_addr_matches_range(uint32_t* minval, uint32_t* x, uint32_t* maxval,
    size_t sz)
{
    size_t i = 0;
    uint8_t checkmin = 1;
    uint8_t checkmax = 1;
    ods_log_assert(sz % 4 == 0);
    /* check treats x as one huge number */
    sz /= 4;
    for (i=0; i<sz; ++i) {
        /* if outside bounds, we are done */
        if (checkmin && minval[i] > x[i]) {
            return 0;
        }
        if (checkmax && maxval[i] < x[i]) {
            return 0;
        }
        /* if x is equal to a bound, that bound needs further checks */
        if (checkmin && minval[i] != x[i]) {
            checkmin = 0;
        }
        if (checkmax && maxval[i]!=x[i]) {
            checkmax = 0;
        }
        if (!checkmin && !checkmax) {
            return 1; /* will always match */
        }
    }
    return 1;
}


/**
 * ACL matches address.
 *
 */
static int
acl_addr_matches(acl_type* acl, struct sockaddr_storage* addr)
{
    if (!acl) {
        return 0;
    }
    if (acl->family == AF_INET6) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*) addr;
        if (addr->ss_family != AF_INET6) {
            return 0;
        }
        if (acl->port != 0 && acl->port != ntohs(addr6->sin6_port)) {
            return 0;
        }
        switch(acl->range_type) {
            case ACL_RANGE_MASK:
            case ACL_RANGE_SUBNET:
                if (!acl_addr_matches_mask((uint32_t*)&acl->addr.addr6,
                    (uint32_t*)&addr6->sin6_addr,
                    (uint32_t*)&acl->range_mask.addr6,
                    sizeof(struct in6_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_MINMAX:
                if (!acl_addr_matches_range((uint32_t*)&acl->addr.addr6,
                    (uint32_t*)&addr6->sin6_addr,
                    (uint32_t*)&acl->range_mask.addr6,
                    sizeof(struct in6_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_SINGLE:
            default:
                if (memcmp(&addr6->sin6_addr, &acl->addr.addr6,
                    sizeof(struct in6_addr)) != 0) {
                    return 0;
                }
                break;
        }
        return 1;
    } else {
        struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
        if (addr4->sin_family != AF_INET) {
            return 0;
        }
        if (acl->port != 0 && acl->port != ntohs(addr4->sin_port)) {
            return 0;
        }
        switch (acl->range_type) {
            case ACL_RANGE_MASK:
            case ACL_RANGE_SUBNET:
                if (!acl_addr_matches_mask((uint32_t*)&acl->addr.addr,
                    (uint32_t*)&addr4->sin_addr,
                    (uint32_t*)&acl->range_mask.addr,
                    sizeof(struct in_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_MINMAX:
                if (!acl_addr_matches_range((uint32_t*)&acl->addr.addr,
                    (uint32_t*)&addr4->sin_addr,
                    (uint32_t*)&acl->range_mask.addr,
                    sizeof(struct in_addr))) {
                    return 0;
                }
                break;
            case ACL_RANGE_SINGLE:
            default:
                if (memcmp(&addr4->sin_addr, &acl->addr.addr,
                    sizeof(struct in_addr)) != 0) {
                    return 0;
                }
                break;
        }
        return 1;
    }
    /* not reached */
    return 0;
}


/**
 * ACL matches TSIG.
 *
 */
static int
acl_tsig_matches(acl_type* acl, void* tsig)
{
    if (!acl) {
        return 0;
    }
    if (!tsig) {
        /* no tsig used */
        return 1;
    }
    /* tsig matches */
    return 1;
}


/**
 * Address storage to IP string.
 *
 */
static char*
addr2ip(struct sockaddr_storage addr, char* ip, size_t len)
{
    if (addr.ss_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
            ip, len)) {
            return NULL;
        }
    } else {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
            ip, len))
            return NULL;
    }
    return ip;
}


/**
 * Find ACL.
 *
 */
acl_type*
acl_find(acl_type* acl, struct sockaddr_storage* addr, void* tsig)
{
    acl_type* find = acl;

    while (find) {
        if (acl_addr_matches(find, addr) && acl_tsig_matches(find, tsig)) {
            ods_log_debug("[%s] match %s", acl_str, find->address);
            return find;
        }
        find = find->next;
    }
    ods_log_debug("[%s] no match", acl_str);
    return NULL;
}


/**
 * Log ACL.
 *
 */
void
acl_log(acl_type* acl)
{
    if (!acl) {
        return;
    }
    ods_log_deeebug("[%s] ACL todo", acl_str);
    return;
}


/**
 * Clean up ACL.
 *
 */
void
acl_cleanup(acl_type* acl, allocator_type* allocator)
{
    if (!acl || !allocator) {
        return;
    }
    acl_cleanup(acl->next, allocator);
    allocator_deallocate(allocator, (void*) acl->address);
    allocator_deallocate(allocator, (void*) acl->tsig_name);
    allocator_deallocate(allocator, (void*) acl);
    return;
}
