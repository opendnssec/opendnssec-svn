/*
 * $Id: sock.h 4958 2011-04-18 07:11:09Z matthijs $
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
 * Sockets.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "shared/log.h"
#include "shared/util.h"
#include "signer/zone.h"
#include "wire/axfr.h"
#include "wire/netio.h"
#include "wire/sock.h"
#include "wire/xfrd.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <unistd.h>

#define SOCK_TCP_BACKLOG 5

static const char* sock_str = "socket";


/**
 * Set udp socket to non-blocking and bind.
 *
 */
static ods_status
sock_fcntl_and_bind(sock_type* sock, const char* node, const char* port,
    const char* stype, const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(stype);
    ods_log_assert(fam);
    if (fcntl(sock->s, F_SETFL, O_NONBLOCK) == -1) {
        ods_log_error("[%s] unable to set %s/%s socket '%s:%s' to "
            "non-blocking: fcntl() failed (%s)", sock_str, stype, fam,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_SOCK_FCNTL_NONBLOCK;
    }
    ods_log_debug("[%s] bind %s/%s socket '%s:%s'", sock_str, stype, fam,
        node?node:"localhost", port, strerror(errno));
    if (bind(sock->s, (struct sockaddr *) sock->addr->ai_addr,
        sock->addr->ai_addrlen) != 0) {
        ods_log_error("[%s] unable to bind %s/%s socket '%s:%s': bind() "
            "failed (%s)", sock_str, stype, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_SOCK_BIND;
    }
    return ODS_STATUS_OK;
}

/**
 * Set socket to v6 only.
 *
 */
static ods_status
sock_v6only(sock_type* sock, const char* node, const char* port, int on,
    const char* stype)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(stype);
#ifdef IPV6_V6ONLY
#if defined(IPPROTO_IPV6)
    ods_log_verbose("[%s] set %s/ipv6 socket '%s:%s' v6only", sock_str,
        stype, node?node:"localhost", port);
    if (setsockopt(sock->s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        ods_log_error("[%s] unable to set %s/ipv6 socket '%s:%s' to "
            "ipv6-only: setsockopt() failed (%s)", sock_str, stype,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_SOCK_SETSOCKOPT_V6ONLY;
    }
#endif
#endif /* IPV6_V6ONLY */
    return ODS_STATUS_OK;
}


/**
 * Set tcp socket to reusable.
 *
 */
static void
sock_tcp_reuseaddr(sock_type* sock, const char* node, const char* port,
    int on, const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(fam);
    if (setsockopt(sock->s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
        ods_log_error("[%s] unable to set tcp/%s socket '%s:%s' to "
            "reuse-addr: setsockopt() failed (%s)", sock_str, fam,
            node?node:"localhost", port, strerror(errno));
    }
    return;
}


/**
 * Listen on tcp socket.
 *
 */
static ods_status
sock_tcp_listen(sock_type* sock, const char* node, const char* port,
    const char* fam)
{
    ods_log_assert(sock);
    ods_log_assert(port);
    ods_log_assert(fam);
    if (listen(sock->s, SOCK_TCP_BACKLOG) == -1) {
        ods_log_error("[%s] unable to listen on tcp/%s socket '%s:%s': "
            "listen() failed (%s)", sock_str, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_SOCK_LISTEN;
    }
    return ODS_STATUS_OK;
}


/**
 * Create server udp socket.
 *
 */
static ods_status
sock_server_udp(sock_type* sock, const char* node, const char* port,
    unsigned* ip6_support)
{
    int on = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(sock);
    ods_log_assert(port);
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif
    *ip6_support = 1;
    /* socket */
    ods_log_debug("[%s] create udp socket '%s:%s'", sock_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_DGRAM, 0))== -1) {
        ods_log_error("[%s] unable to create udp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", sock_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_SOCKET_UDP;
    }
    /* ipv4 */
    if (sock->addr->ai_family == AF_INET) {
        status = sock_fcntl_and_bind(sock, node, port, "udp", "ipv4");
    }
    /* ipv6 */
    else if (sock->addr->ai_family == AF_INET6) {
        status = sock_v6only(sock, node, port, on, "udp");
        if (status != ODS_STATUS_OK) {
            return status;
        }
        status = sock_fcntl_and_bind(sock, node, port, "udp", "ipv6");
    }
    return status;
}


/**
 * Create server tcp socket.
 *
 */
static ods_status
sock_server_tcp(sock_type* sock, const char* node, const char* port,
    unsigned* ip6_support)
{
    int on = 0;
    ods_status status = ODS_STATUS_OK;
    ods_log_assert(sock);
    ods_log_assert(port);
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif
    *ip6_support = 1;
    /* socket */
    ods_log_debug("[%s] create tcp socket '%s:%s'", sock_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_STREAM, 0))== -1) {
        ods_log_error("[%s] unable to create tcp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", sock_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_SOCKET_TCP;
    }
    /* ipv4 */
    if (sock->addr->ai_family == AF_INET) {
        sock_tcp_reuseaddr(sock, node, port, on, "ipv4");
        status = sock_fcntl_and_bind(sock, node, port, "tcp", "ipv4");
        if (status == ODS_STATUS_OK) {
            status = sock_tcp_listen(sock, node, port, "ipv4");
        }
    }
    /* ipv6 */
    else if (sock->addr->ai_family == AF_INET6) {
        status = sock_v6only(sock, node, port, on, "tcp");
        if (status != ODS_STATUS_OK) {
            return status;
        }
        sock_tcp_reuseaddr(sock, node, port, on, "ipv6");
        status = sock_fcntl_and_bind(sock, node, port, "tcp", "ipv6");
        if (status == ODS_STATUS_OK) {
            status = sock_tcp_listen(sock, node, port, "ipv6");
        }
    }
    return status;
}


/**
 * Create listening socket.
 *
 */
static ods_status
socket_listen(sock_type* sock, struct addrinfo hints, int socktype,
    const char* node, const char* port, unsigned* ip6_support)
{
    ods_status status = ODS_STATUS_OK;
    int r = 0;
    ods_log_assert(sock);
    ods_log_assert(port);
    *ip6_support = 1;
    hints.ai_socktype = socktype;
    /* getaddrinfo */
    if ((r = getaddrinfo(node, port, &hints, &sock->addr)) != 0 ||
        !sock->addr) {
        ods_log_error("[%s] unable to parse address '%s:%s': getaddrinfo() "
            "failed (%s %s)", sock_str, node?node:"localhost", port,
            gai_strerror(r),
#ifdef EAI_SYSTEM
            r==EAI_SYSTEM?(char*)strerror(errno):"");
#else
            "");
#endif
        if (hints.ai_family == AF_INET6 && r==EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_SOCK_GETADDRINFO;
    }
    /* socket */
    if (socktype == SOCK_DGRAM) {
        status = sock_server_udp(sock, node, port, ip6_support);
    } else if (socktype == SOCK_STREAM) {
        status = sock_server_tcp(sock, node, port, ip6_support);
    }
    ods_log_debug("[%s] socket listening to %s:%s", sock_str,
        node?node:"localhost", port);
    return status;
}


/**
 * Create sockets and listen.
 *
 */
ods_status
sock_listen(socklist_type* sockets, listener_type* listener)
{
    ods_status status = ODS_STATUS_OK;
    struct addrinfo hints[MAX_INTERFACES];
    const char* node = NULL;
    const char* port = NULL;
    size_t i = 0;
    unsigned ip6_support = 1;

    if (!sockets || !listener) {
        return ODS_STATUS_ASSERT_ERR;
    }
    /* Initialize values */
    for (i = 0; i < MAX_INTERFACES; i++) {
        memset(&hints[i], 0, sizeof(hints[i]));
        hints[i].ai_family = AF_UNSPEC;
        hints[i].ai_flags = AI_PASSIVE;
        sockets->udp[i].s = -1;
        sockets->tcp[i].s = -1;
    }
    /* Walk interfaces */
    for (i=0; i < listener->count; i++) {
        node = NULL;
        if (strlen(listener->interfaces[i].address) > 0) {
            node = listener->interfaces[i].address;
        }
        port = DNS_PORT_STRING;
        if (listener->interfaces[i].port) {
            port = listener->interfaces[i].port;
        }
        if (node != NULL) {
            hints[i].ai_flags |= AI_NUMERICHOST;
        } else {
            hints[i].ai_family = listener->interfaces[i].family;
        }
        /* udp */
        status = socket_listen(&sockets->udp[i], hints[i], SOCK_DGRAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", sock_str);
                status = ODS_STATUS_OK;
            } else {
                return status;
            }
        }
        /* tcp */
        status = socket_listen(&sockets->tcp[i], hints[i], SOCK_STREAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", sock_str);
                status = ODS_STATUS_OK;
            } else {
                return status;
            }
        }

    }
    /* All ok */
    return ODS_STATUS_OK;
}


/**
 * Send data over udp.
 *
 */
static void
send_udp(struct udp_data* data)
{
    ssize_t nb;
    nb = sendto(data->socket->s, buffer_begin(data->query->buffer),
        buffer_remaining(data->query->buffer), 0,
        (struct sockaddr*) &data->query->addr, data->query->addrlen);
    if (nb == -1) {
        ods_log_error("[%s] unable to send data over udp: sendto() failed "
            "(%s)", sock_str, strerror(errno));
    } else if ((size_t) nb != buffer_remaining(data->query->buffer)) {
        ods_log_error("[%s] unable to send data over udp: only sent %d of %d "
            "octets", sock_str, (int)nb,
            (int)buffer_remaining(data->query->buffer));
    }
    return;
}


/*
 * Handle error.
 *
 */
static void
sock_send_error(ldns_pkt* pkt, ldns_pkt_rcode rcode,
    void (*sendfunc)(uint8_t*, size_t, void*), void* userdata)
{
    uint8_t *outbuf = NULL;
    size_t answer_size = 0;
    ldns_status status = LDNS_STATUS_OK;

    if (!pkt) {
        return;
    }
    ldns_pkt_set_qr(pkt, 1);
    ldns_pkt_set_rcode(pkt, rcode);
    ldns_pkt_set_ancount(pkt, 0);
    ldns_pkt_set_nscount(pkt, 0);
    ldns_pkt_set_arcount(pkt, 0);

    status = ldns_pkt2wire(&outbuf, pkt, &answer_size);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to send dns error: ldns_pkt2wire() "
            "failed (%s)", sock_str, ldns_get_errorstr_by_id(status));
        return;
    }
    sendfunc(outbuf, answer_size, userdata);
    LDNS_FREE(outbuf);
    return;
}


/**
 * Handle NOTIFY.
 *
 */
static void
sock_handle_notify(ldns_pkt* pkt, ldns_rr* rr, engine_type* engine,
    zone_type* zone, void (*sendfunc)(uint8_t*, size_t, void*),
    void* userdata)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr_list* answer_section = NULL;
    uint8_t *outbuf = NULL;
    size_t answer_size = 0;

    if (!pkt || !rr || !engine || !zone) {
        sock_send_error(pkt, LDNS_RCODE_FORMERR, sendfunc, userdata);
        return;
    }
    if (ldns_pkt_get_rcode(pkt) != LDNS_RCODE_NOERROR ||
        ldns_pkt_qr(pkt) ||
        !ldns_pkt_aa(pkt) ||
        ldns_pkt_tc(pkt) ||
        ldns_pkt_rd(pkt) ||
        ldns_pkt_ra(pkt) ||
        ldns_pkt_cd(pkt) ||
        ldns_pkt_ad(pkt) ||
        ldns_pkt_qdcount(pkt) != 1 ||
        ldns_pkt_ancount(pkt) > 1 ||
        ldns_pkt_nscount(pkt) != 0 ||
        ldns_pkt_arcount(pkt) != 0 ||
        ldns_rr_get_type(rr) != LDNS_RR_TYPE_SOA ||
        ldns_rr_get_class(rr) != LDNS_RR_CLASS_IN) {
        sock_send_error(pkt, LDNS_RCODE_FORMERR, sendfunc, userdata);
        return;
    }
    /* notify ok */
    ods_log_debug("[%s] notify ok", sock_str);
    ldns_pkt_set_qr(pkt, 1);
    status = ldns_pkt2wire(&outbuf, pkt, &answer_size);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] unable to send notify ok: ldns_pkt2wire() "
            "failed (%s)", sock_str, ldns_get_errorstr_by_id(status));
        return;
    }
    sendfunc(outbuf, answer_size, userdata);

    answer_section = ldns_pkt_answer(pkt);
    if (answer_section && ldns_rr_list_rr_count(answer_section) == 1) {
        lock_basic_lock(&zone->xfrd->serial_lock);
        zone->xfrd->serial_notify = ldns_rdf2native_int32(
            ldns_rr_rdf(ldns_rr_list_rr(answer_section, 0),
            SE_SOA_RDATA_SERIAL));
        zone->xfrd->serial_notify_acquired = time_now();
        if (!util_serial_gt(zone->xfrd->serial_notify,
            zone->xfrd->serial_disk)) {
            ods_log_verbose("[%s] already got zone %s serial %u on disk",
                sock_str, zone->name, zone->xfrd->serial_notify);
            lock_basic_unlock(&zone->xfrd->serial_lock);
            LDNS_FREE(outbuf);
            return;
        }
        lock_basic_unlock(&zone->xfrd->serial_lock);
    } else {
        lock_basic_lock(&zone->xfrd->serial_lock);
        zone->xfrd->serial_notify = 0;
        zone->xfrd->serial_notify_acquired = 0;
        lock_basic_unlock(&zone->xfrd->serial_lock);
    }

    /* request xfr */
    xfrd_set_timer_now(zone->xfrd);
    dnshandler_fwd_notify(engine->dnshandler, outbuf, answer_size);
    LDNS_FREE(outbuf);
    return;
}


/**
 * Handle QUERY.
 *
 */
/*
static void
sock_handle_transfer(ldns_pkt* pkt, ldns_rr* rr, engine_type* engine,
    zone_type* zone, void (*sendfunc)(uint8_t*, size_t, void*), int is_tcp,
    void* userdata)
{
    if (!pkt || !rr || !engine || !zone) {
        sock_send_error(pkt, LDNS_RCODE_FORMERR, sendfunc, userdata);
        return;
    }
    if (ldns_pkt_get_rcode(pkt) != LDNS_RCODE_NOERROR ||
        ldns_pkt_qr(pkt) ||
        ldns_pkt_aa(pkt) ||
        ldns_pkt_tc(pkt) ||
        ldns_pkt_ra(pkt) ||
        ldns_pkt_qdcount(pkt) != 1 ||
        ldns_pkt_ancount(pkt) > 1 ||
        ldns_rr_get_class(rr) != LDNS_RR_CLASS_IN) {
        sock_send_error(pkt, LDNS_RCODE_FORMERR, sendfunc, userdata);
        return;
    }
    if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_IXFR &&
        (ldns_pkt_nscount(pkt) != 0 || ldns_pkt_arcount(pkt) != 0)) {
        sock_send_error(pkt, LDNS_RCODE_FORMERR, sendfunc, userdata);
        return;
    }

    switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_AXFR:
             add axfr to answer section
            if (is_tcp) {
                struct tcp_data *ud =
                    (struct tcp_data*) userdata;
                query_reset(ud->socket->query, TCP_MAX_MESSAGE_LEN, 1);
                axfr(ud->socket->query, engine);
            }
        case LDNS_RR_TYPE_IXFR:
            search serial
            add ixfr to answer section
        case LDNS_RR_TYPE_SOA:
            add soa to answer section
            add ns to auth section
            add glues to addition section
        default:
            sock_send_error(pkt, LDNS_RCODE_NOTIMPL, sendfunc, userdata);
            return;
    }
    default
    sock_send_error(pkt, LDNS_RCODE_NOTIMPL, sendfunc, userdata);
    return;
}
*/


/**
 * Handle query.
 *
 */
/*
static void
sock_handle_query(ldns_pkt* pkt, ldns_rr* rr, engine_type* engine,
    zone_type* zone, void (*sendfunc)(uint8_t*, size_t, void*),
    int is_tcp, void* userdata)
{
    ods_log_assert(zone);
    ods_log_assert(pkt);
    ods_log_assert(rr);
    if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_NOTIFY) {
        sock_handle_notify(pkt, rr, engine, zone, sendfunc, userdata);
    } else if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_QUERY) {
        sock_handle_transfer(pkt, rr, engine, zone, sendfunc, is_tcp,
            userdata);
    } else if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_UPDATE) {
        ods_log_verbose("[%s] received update", sock_str);
    } else {
        ods_log_verbose("[%s] received bogus packet", sock_str);
    }
    return;
}
*/

/**
 * Check address against ACL.
 *
 */
static ldns_pkt_rcode
sock_acl_matches(struct sockaddr_storage* addr, ldns_pkt* pkt,
    zone_type* zone)
{
    dnsin_type* dnsin = NULL;
    dnsout_type* dnsout = NULL;

    if (!addr || !pkt) {
        return LDNS_RCODE_FORMERR;
    }
    if (!zone) {
        return LDNS_RCODE_NXDOMAIN;
    }
    ods_log_assert(zone);
    ods_log_assert(zone->name);
    if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_NOTIFY) {
        if (!zone->adinbound || zone->adinbound->type != ADAPTER_DNS) {
            return LDNS_RCODE_SERVFAIL;
        }
        ods_log_assert(zone->adinbound->config);
        dnsin = (dnsin_type*) zone->adinbound->config;
        if (acl_find(dnsin->allow_notify, addr, NULL)) {
            return LDNS_RCODE_NOERROR;
        } else {
            return LDNS_RCODE_REFUSED;
        }
    } else if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_QUERY) {
        if (!zone->adoutbound || zone->adoutbound->type != ADAPTER_DNS) {
            return LDNS_RCODE_SERVFAIL;
        }
        ods_log_assert(zone->adoutbound->config);
        dnsout = (dnsout_type*) zone->adoutbound->config;
        if (acl_find(dnsout->provide_xfr, addr, NULL)) {
            return LDNS_RCODE_NOERROR;
        } else {
            return LDNS_RCODE_REFUSED;
        }
    } else if (ldns_pkt_get_opcode(pkt) == LDNS_PACKET_UPDATE) {
        return LDNS_RCODE_NOTIMPL;
    } else {
        ods_log_verbose("[%s] received bogus packet", sock_str);
        return LDNS_RCODE_FORMERR;
    }
    return LDNS_RCODE_SERVFAIL;
}


/**
 * Parse incoming DNS packet.
 *
 */
static ods_status
sock_parse_packet(uint8_t* inbuf, ssize_t inlen, engine_type* e,
    ldns_pkt** pkt, ldns_rr** rr, zone_type** zone)
{
    ldns_status status = LDNS_STATUS_OK;
    /* packet parsing */
    status = ldns_wire2pkt(pkt, inbuf, (size_t)inlen);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] got bad packet: %s", sock_str,
            ldns_get_errorstr_by_id(status));
        return ODS_STATUS_ERR;
    }
    *rr = ldns_rr_list_rr(ldns_pkt_question(*pkt), 0);
    /* lookup zone */
    ods_log_assert(e);
    lock_basic_lock(&e->zonelist->zl_lock);
    *zone = zonelist_lookup_zone_by_dname(e->zonelist, ldns_rr_owner(*rr),
        ldns_rr_get_class(*rr));
    if (*zone && (*zone)->zl_status == ZONE_ZL_ADDED) {
        *zone = NULL;
    }
    lock_basic_unlock(&e->zonelist->zl_lock);
    return ODS_STATUS_OK;
}


/**
 * Handle incoming udp queries.
 *
 */
void
sock_handle_udp(netio_type* ATTR_UNUSED(netio), netio_handler_type* handler,
    netio_events_type event_types)
{
    struct udp_data* data = (struct udp_data*) handler->user_data;
    int received = 0;
    query_type* q = data->query;
    query_state qstate = QUERY_PROCESSED;

    if (!(event_types & NETIO_EVENT_READ)) {
        return;
    }
    query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
    received = recvfrom(handler->fd, buffer_begin(q->buffer),
        buffer_remaining(q->buffer), 0, (struct sockaddr*) &q->addr,
        &q->addrlen);
    if (received < 1) {
        if (errno != EAGAIN && errno != EINTR) {
            ods_log_error("[%s] recvfrom() failed: %s", sock_str,
                strerror(errno));
        }
        return;
    }
    buffer_skip(q->buffer, received);
    buffer_flip(q->buffer);
    buffer_pkt_print(stdout, q->buffer);
    /* acl */
    qstate = query_process(q, data->engine);

    /* edns */
    /* tsig */
    if (qstate != QUERY_DISCARDED) {
        buffer_pkt_print(stdout, q->buffer);
        send_udp(data);
    }
    return;
}


/**
 * Cleanup tcp handler data.
 *
 */
static void
cleanup_tcp_handler(netio_type* netio, netio_handler_type* handler)
{
    struct tcp_data* data = (struct tcp_data*) handler->user_data;
    allocator_type* allocator = data->allocator;
    netio_remove_handler(netio, handler);
    close(handler->fd);
    allocator_deallocate(allocator, (void*) handler->timeout);
    allocator_deallocate(allocator, (void*) handler);
    query_cleanup(data->query);
    allocator_deallocate(allocator, (void*) data);
    allocator_cleanup(allocator);
    return;
}


/**
 * Handle incoming tcp connections.
 *
 */
void
sock_handle_tcp_accept(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    allocator_type* allocator = NULL;
    struct tcp_accept_data* accept_data = (struct tcp_accept_data*)
        handler->user_data;
    int s = 0;
    struct tcp_data* tcp_data = NULL;
    netio_handler_type* tcp_handler = NULL;
    struct sockaddr_storage addr;
    socklen_t addrlen = 0;

    ods_log_debug("[%s] handle incoming tcp connection", sock_str);

    if (!(event_types & NETIO_EVENT_READ)) {
        return;
    }
    addrlen = sizeof(addr);
    s = accept(handler->fd, (struct sockaddr *) &addr, &addrlen);
    if (s == -1) {
        if (errno != EINTR && errno != EWOULDBLOCK) {
            ods_log_error("[%s] unable to handle incoming tcp connection: "
                "accept() failed (%s)", sock_str, strerror(errno));
        }
        return;
    }
    if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "fcntl() failed: %s", sock_str, strerror(errno));
        close(s);
        return;
    }

    /* create tcp handler data */
    allocator = allocator_create(malloc, free);
    if (!allocator) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "allocator_create() failed", sock_str);
        close(s);
        return;
    }
    tcp_data = (struct tcp_data*) allocator_alloc(allocator,
        sizeof(struct tcp_data));
    if (!tcp_data) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "allocator_alloc() data failed", sock_str);
        allocator_cleanup(allocator);
        close(s);
        return;
    }
    tcp_data->allocator = allocator;
    tcp_data->query = query_create();
    if (!tcp_data->query) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "query_create() failed", sock_str);
        allocator_deallocate(allocator, (void*) tcp_data);
        allocator_cleanup(allocator);
        close(s);
        return;
    }
    tcp_data->engine = accept_data->engine;
    tcp_data->tcp_accept_handler_count =
        accept_data->tcp_accept_handler_count;
    tcp_data->tcp_accept_handlers = accept_data->tcp_accept_handlers;
    tcp_data->qstate = QUERY_PROCESSED;
    tcp_data->bytes_transmitted = 0;
    memcpy(&tcp_data->query->addr, &addr, addrlen);
    tcp_data->query->addrlen = addrlen;

    tcp_handler = (netio_handler_type*) allocator_alloc(allocator,
        sizeof(netio_handler_type));
    if (!tcp_data) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "allocator_alloc() handler failed", sock_str);
        query_cleanup(tcp_data->query);
        allocator_deallocate(allocator, (void*) tcp_data);
        allocator_cleanup(allocator);
        close(s);
        return;
    }
    tcp_handler->fd = s;
    tcp_handler->timeout = (struct timespec*) allocator_alloc(allocator,
        sizeof(struct timespec));
    if (!tcp_handler->timeout) {
        ods_log_error("[%s] unable to handle incoming tcp connection: "
            "allocator_alloc() timeout failed", sock_str);
        allocator_deallocate(allocator, (void*) tcp_handler);
        query_cleanup(tcp_data->query);
        allocator_deallocate(allocator, (void*) tcp_data);
        allocator_cleanup(allocator);
        close(s);
        return;
    }
    tcp_handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    tcp_handler->timeout->tv_nsec = 0L;
    timespec_add(tcp_handler->timeout, netio_current_time(netio));
    tcp_handler->user_data = tcp_data;
    tcp_handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
    tcp_handler->event_handler = sock_handle_tcp_read;
    netio_add_handler(netio, tcp_handler);
    return;
}


/**
 * Handle incoming tcp queries.
 *
 */
void
sock_handle_tcp_read(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    struct tcp_data* data = (struct tcp_data *) handler->user_data;
    ssize_t received = 0;
    query_state qstate = QUERY_PROCESSED;

    if (event_types & NETIO_EVENT_TIMEOUT) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    ods_log_assert(event_types & NETIO_EVENT_READ);
    if (data->bytes_transmitted == 0) {
        query_reset(data->query, TCP_MAX_MESSAGE_LEN, 1);
    }
    /* check if we received the leading packet length bytes yet. */
    if (data->bytes_transmitted < sizeof(uint16_t)) {
        received = read(handler->fd,
            (char *) &data->query->tcplen + data->bytes_transmitted,
            sizeof(uint16_t) - data->bytes_transmitted);
         if (received == -1) {
             if (errno == EAGAIN || errno == EINTR) {
                 /* read would block, wait until more data is available. */
                 return;
             } else {
                 ods_log_error("[%s] unable to handle incoming tcp query: "
                     "read() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
             }
         } else if (received == 0) {
             cleanup_tcp_handler(netio, handler);
             return;
         }
         data->bytes_transmitted += received;
         if (data->bytes_transmitted < sizeof(uint16_t)) {
             /* not done with the tcplen yet, wait for more. */
             return;
         }
         ods_log_assert(data->bytes_transmitted == sizeof(uint16_t));
         data->query->tcplen = ntohs(data->query->tcplen);
         /* minimum query size is: 12 + 1 + 2 + 2:
          * header size + root dname + qclass + qtype */
         if (data->query->tcplen < 17) {
             ods_log_warning("[%s] unable to handle incoming tcp query: "
                 "packet too small", sock_str);
             cleanup_tcp_handler(netio, handler);
             return;
         }
         if (data->query->tcplen > data->query->maxlen) {
             ods_log_warning("[%s] unable to handle incoming tcp query: "
                 "insufficient tcp buffer", sock_str);
             cleanup_tcp_handler(netio, handler);
             return;
         }
         buffer_set_limit(data->query->buffer, data->query->tcplen);
    }
    ods_log_assert(buffer_remaining(data->query->buffer) > 0);
    /* read the (remaining) query data.  */
    received = read(handler->fd, buffer_current(data->query->buffer),
        buffer_remaining(data->query->buffer));
    if (received == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* read would block, wait until more data is available. */
            return;
        } else {
                 ods_log_error("[%s] unable to handle incoming tcp query: "
                     "read() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
        }
    } else if (received == 0) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    data->bytes_transmitted += received;
    buffer_skip(data->query->buffer, received);
    if (buffer_remaining(data->query->buffer) > 0) {
        /* not done with message yet, wait for more. */
        return;
    }
    ods_log_assert(buffer_position(data->query->buffer) ==
        data->query->tcplen);
    /* we have a complete query, process it. */
    buffer_flip(data->query->buffer);
    buffer_pkt_print(stdout, data->query->buffer);
    /* acl */
    qstate = query_process(data->query, data->engine);
    if (qstate != QUERY_DISCARDED) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    /* edns */
    /* tsig */
    /* switch to tcp write handler. */
    buffer_pkt_print(stdout, data->query->buffer);
    data->query->tcplen = buffer_remaining(data->query->buffer);
    data->bytes_transmitted = 0;
    handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    handler->timeout->tv_nsec = 0L;
    timespec_add(handler->timeout, netio_current_time(netio));
    handler->event_types = NETIO_EVENT_WRITE | NETIO_EVENT_TIMEOUT;
    handler->event_handler = sock_handle_tcp_write;
    return;
}


/**
 * Handle outgoing tcp responses.
 *
 */
void
sock_handle_tcp_write(netio_type* netio, netio_handler_type* handler,
    netio_events_type event_types)
{
    struct tcp_data* data = (struct tcp_data *) handler->user_data;
    ssize_t sent = 0;
    query_type* q = data->query;

    if (event_types & NETIO_EVENT_TIMEOUT) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    ods_log_assert(event_types & NETIO_EVENT_WRITE);
    if (data->bytes_transmitted < sizeof(q->tcplen)) {
        uint16_t n_tcplen = htons(q->tcplen);
        sent = write(handler->fd,
            (const char*) &n_tcplen + data->bytes_transmitted,
            sizeof(n_tcplen) - data->bytes_transmitted);
        if (sent == -1) {
             if (errno == EAGAIN || errno == EINTR) {
                 /* write would block, wait until socket becomes writeable. */
                 return;
             } else {
                 ods_log_error("[%s] unable to handle outgoing tcp response: "
                     "write() failed (%s)", sock_str, strerror(errno));
                 cleanup_tcp_handler(netio, handler);
                 return;
             }
         } else if (sent == 0) {
             cleanup_tcp_handler(netio, handler);
             return;
         }
         data->bytes_transmitted += sent;
         if (data->bytes_transmitted < sizeof(q->tcplen)) {
             /* writing not complete, wait until socket becomes writable. */
             return;
         }
         ods_log_assert(data->bytes_transmitted == sizeof(q->tcplen));
    }
    ods_log_assert(data->bytes_transmitted < q->tcplen + sizeof(q->tcplen));

    sent = write(handler->fd, buffer_current(q->buffer),
        buffer_remaining(q->buffer));
    if (sent == -1) {
        if (errno == EAGAIN || errno == EINTR) {
            /* write would block, wait until socket becomes writeable. */
            return;
        } else {
            ods_log_error("[%s] unable to handle outgoing tcp response: "
                 "write() failed (%s)", sock_str, strerror(errno));
            cleanup_tcp_handler(netio, handler);
            return;
        }
    } else if (sent == 0) {
        cleanup_tcp_handler(netio, handler);
        return;
    }
    buffer_skip(q->buffer, sent);
    data->bytes_transmitted += sent;
    if (data->bytes_transmitted < q->tcplen + sizeof(q->tcplen)) {
        /* still more data to write when socket becomes writable. */
        return;
    }
    ods_log_assert(data->bytes_transmitted == q->tcplen + sizeof(q->tcplen));
    if (data->qstate == QUERY_AXFR) {
        /* continue processing AXFR and writing back results.  */
        buffer_clear(q->buffer);
        data->qstate = axfr(q, data->engine);
        if (data->qstate != QUERY_PROCESSED) {
            /* edns, tsig */
            buffer_flip(q->buffer);
            q->tcplen = buffer_remaining(q->buffer);
            data->bytes_transmitted = 0;
            handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
            handler->timeout->tv_nsec = 0L;
            timespec_add(handler->timeout, netio_current_time(netio));
            return;
        }
    }
    /* done sending, wait for the next request. */
    data->bytes_transmitted = 0;
    handler->timeout->tv_sec = XFRD_TCP_TIMEOUT;
    handler->timeout->tv_nsec = 0L;
    timespec_add(handler->timeout, netio_current_time(netio));
    handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
    handler->event_handler = sock_handle_tcp_read;
    return;
}
