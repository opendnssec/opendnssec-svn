/*
 * $Id: netio.h 4958 2011-04-18 07:11:09Z matthijs $
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
 * Network input and output.
 *
 */

#include "config.h"
#include "daemon/engine.h"
#include "shared/log.h"
#include "wire/netio.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <unistd.h>

#define NETIO_TCP_BACKLOG 5

static const char* netio_str = "netio";


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
            "non-blocking: fcntl() failed (%s)", netio_str, stype, fam,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_NETIO_FCNTL_NONBLOCK;
    }
    ods_log_debug("[%s] bind %s/%s socket '%s:%s'", netio_str, stype, fam,
        node?node:"localhost", port, strerror(errno));
    if (bind(sock->s, (struct sockaddr *) sock->addr->ai_addr,
        sock->addr->ai_addrlen) != 0) {
        ods_log_error("[%s] unable to bind %s/%s socket '%s:%s': bind() "
            "failed (%s)", netio_str, stype, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_NETIO_BIND;
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
    ods_log_verbose("[%s] set %s/ipv6 socket '%s:%s' v6only", netio_str,
        stype, node?node:"localhost", port);
    if (setsockopt(sock->s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0) {
        ods_log_error("[%s] unable to set %s/ipv6 socket '%s:%s' to "
            "ipv6-only: setsockopt() failed (%s)", netio_str, stype,
            node?node:"localhost", port, strerror(errno));
        return ODS_STATUS_NETIO_SETSOCKOPT_V6ONLY;
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
            "reuse-addr: setsockopt() failed (%s)", netio_str, fam,
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
    if (listen(sock->s, NETIO_TCP_BACKLOG) == -1) {
        ods_log_error("[%s] unable to listen on tcp/%s socket '%s:%s': "
            "listen() failed (%s)", netio_str, fam, node?node:"localhost",
            port, strerror(errno));
        return ODS_STATUS_NETIO_LISTEN;
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
    ods_log_debug("[%s] create udp socket '%s:%s'", netio_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_DGRAM, 0))== -1) {
        ods_log_error("[%s] unable to create udp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", netio_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_NETIO_SOCKET_UDP;
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
    ods_log_debug("[%s] create tcp socket '%s:%s'", netio_str,
        node?node:"localhost", port, strerror(errno));
    if ((sock->s = socket(sock->addr->ai_family, SOCK_STREAM, 0))== -1) {
        ods_log_error("[%s] unable to create tcp/ipv4 socket '%s:%s': "
            "socket() failed (%s)", netio_str, node?node:"localhost", port,
            strerror(errno));
        if (sock->addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_NETIO_SOCKET_TCP;
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
sock_listen(sock_type* sock, struct addrinfo hints, int socktype,
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
            "failed (%s %s)", netio_str, node?node:"localhost", port,
            gai_strerror(r),
#ifdef EAI_SYSTEM
            r==EAI_SYSTEM?(char*)strerror(errno):"");
#else
            "");
#endif
        if (hints.ai_family == AF_INET6 && r==EAFNOSUPPORT) {
            *ip6_support = 0;
        }
        return ODS_STATUS_NETIO_GETADDRINFO;
    }
    /* socket */
    if (socktype == SOCK_DGRAM) {
        status = sock_server_udp(sock, node, port, ip6_support);
    } else if (socktype == SOCK_STREAM) {
        status = sock_server_tcp(sock, node, port, ip6_support);
    }
    ods_log_debug("[%s] socket listening to %s:%s", netio_str,
        node?node:"localhost", port);
    return status;
}


/**
 * Create sockets and listen.
 *
 */
ods_status
sockets_listen(socklist_type* sockets, listener_type* listener)
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
        status = sock_listen(&sockets->udp[i], hints[i], SOCK_DGRAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", netio_str);
                status = ODS_STATUS_OK;
            } else {
                return status;
            }
        }

        /* tcp */
        status = sock_listen(&sockets->tcp[i], hints[i], SOCK_STREAM,
            node, port, &ip6_support);
        if (status != ODS_STATUS_OK) {
            if (!ip6_support) {
                ods_log_warning("[%s] fallback to udp/ipv4, no udp/ipv6: "
                    "not supported", netio_str);
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
 * Send data over tcp.
 *
 */
static void
send_udp(uint8_t* buf, size_t len, void* data)
{
    struct handle_udp_userdata *userdata = (struct handle_udp_userdata*)data;
    ssize_t nb;
    nb = sendto(userdata->udp_sock, buf, len, 0,
        (struct sockaddr*)&userdata->addr_him, userdata->hislen);
    if (nb == -1) {
        ods_log_error("[%s] unable to send data over udp: sendto() failed "
            "(%s)", netio_str, strerror(errno));
    } else if ((size_t) nb != len) {
        ods_log_error("[%s] unable to send data over udp: only sent %d of %d "
            "octets", netio_str, (int)nb, (int)len);
    }
    return;
}


/**
 * Send data over tcp.
 *
 */
static void
write_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = send(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            ods_log_error("[%s] unable to send data over tcp: send() failed "
                "(%s)", netio_str, strerror(errno));
            return;
        }
        count += nb;
    }
    return;
}
static void
send_tcp(uint8_t* buf, size_t len, void* data)
{
    struct handle_tcp_userdata *userdata = (struct handle_tcp_userdata*)data;
    uint16_t tcplen;
    tcplen = htons(len);
    write_n_bytes(userdata->s, (uint8_t*)&tcplen, sizeof(tcplen));
    write_n_bytes(userdata->s, buf, len);
    return;
}


/**
 * Handle query.
 *
 */
static void
netio_handle_query(uint8_t* inbuf, ssize_t inlen,
    void (*sendfunc)(uint8_t*, size_t, void*), void* userdata, void* engine)
{
    engine_type* e = (engine_type*) engine;
    zone_type* zone = NULL;
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt *query_pkt = NULL;
    ldns_rr *query_rr = NULL;
    uint8_t *outbuf = NULL;
    size_t answer_size = 0;
    /* packet parsing */
    status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)inlen);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("[%s] got bad packet: %s", netio_str,
            ldns_get_errorstr_by_id(status));
        return;
    }
    query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);

    if (ldns_pkt_get_opcode(query_pkt) == LDNS_PACKET_NOTIFY) {
        ods_log_verbose("[%s] received NOTIFY", netio_str);
        /* lookup zone */
        ods_log_assert(e);
        zone = zonelist_lookup_zone_by_dname(e->zonelist,
            ldns_rr_owner(query_rr), ldns_rr_get_class(query_rr));

        /* NOTIFY OK */
        ldns_pkt_set_qr(query_pkt, 1);
        status = ldns_pkt2wire(&outbuf, query_pkt, &answer_size);
        if (status != LDNS_STATUS_OK) {
            ods_log_error("[%s] unable to send NOTIFY OK: ldns_pkt2wire() "
                "failed (%s)", netio_str, ldns_get_errorstr_by_id(status));
            return;
        }
        sendfunc(outbuf, answer_size, userdata);
        LDNS_FREE(outbuf);

    } else if (ldns_pkt_get_opcode(query_pkt) == LDNS_PACKET_QUERY) {
        ods_log_verbose("[%s] received QUERY", netio_str);
    } else if (ldns_pkt_get_opcode(query_pkt) == LDNS_PACKET_UPDATE) {
        ods_log_verbose("[%s] received UPDATE", netio_str);
    } else {
        ods_log_verbose("[%s] received bogus packet", netio_str);
    }
    return;
}


/*
 * Handle udp.
 *
 */
void
netio_handle_udp(int s, void* engine)
{
    ssize_t nb;
    uint8_t inbuf[INBUF_SIZE];
    struct handle_udp_userdata userdata;
    if (!engine) {
        return;
    }
    userdata.udp_sock = s;
    userdata.hislen = (socklen_t) sizeof(userdata.addr_him);
    /* recv */
    nb = recvfrom(s, inbuf, INBUF_SIZE, 0,
        (struct sockaddr*) &userdata.addr_him, &userdata.hislen);
    if (nb < 1) {
        ods_log_error("[%s] recvfrom() failed: %s", netio_str,
            strerror(errno));
        return;
    }
    /* acl */
    netio_handle_query(inbuf, nb, send_udp, &userdata, engine);
    return;
}


static void
read_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = recv(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            ods_log_error("[%s] recv() failed: %s", netio_str,
                strerror(errno));
            return;
        }
        count += nb;
    }
    return;
}


/*
 * Handle tcp.
 *
 */
void
netio_handle_tcp(int s, void* engine)
{
    int tcp_s;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
    uint8_t inbuf[INBUF_SIZE];
    uint16_t tcplen;
    struct handle_tcp_userdata userdata;
    if (!engine) {
        return;
    }
    /* accept */
    hislen = (socklen_t)sizeof(addr_him);
    if((tcp_s = accept(s, (struct sockaddr*)&addr_him, &hislen)) < 0) {
        ods_log_error("[%s] accept() failed: %s", netio_str, strerror(errno));
        return;
    }
    userdata.s = tcp_s;
    /* tcp recv */
    read_n_bytes(tcp_s, (uint8_t*)&tcplen, sizeof(tcplen));
    tcplen = ntohs(tcplen);
    if(tcplen >= INBUF_SIZE) {
        ods_log_error("zone fetcher query %d bytes too large, "
            "buffer %d bytes.", tcplen, INBUF_SIZE);
        close(tcp_s);
        return;
    }
    read_n_bytes(tcp_s, inbuf, tcplen);
    /* acl */
    netio_handle_query(inbuf, (ssize_t) tcplen, send_tcp, &userdata, engine);
    close(tcp_s);
    return;
}
