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

#ifndef WIRE_SOCK_H
#define WIRE_SOCK_H

#include "config.h"
#include "shared/status.h"
#include "wire/listener.h"
#include "wire/query.h"

/**
 * Sockets.
 */
typedef struct sock_struct sock_type;
struct sock_struct {
    struct addrinfo* addr;
    int s;
    query_type* query;
};

typedef struct socklist_struct socklist_type;
struct socklist_struct {
    sock_type tcp[MAX_INTERFACES];
    sock_type udp[MAX_INTERFACES];
};

/**
 * User data.
 */
struct handle_udp_userdata {
    sock_type udp_sock;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
};

struct handle_tcp_userdata {
    int s;
    sock_type tcp_sock;
};

/**
 * Create sockets and listen.
 * \param[out] sockets sockets
 * \param[in] listener interfaces
 * \return ods_status status
 *
 */
ods_status sock_listen(socklist_type* sockets, listener_type* listener);

/**
 * Handle udp.
 * \param[in] s socket
 * \param[in] engine signer engine reference
 *
 */
void sock_handle_udp(sock_type s, void* engine);

/**
 * Handle tcp.
 * \param[in] s socket
 * \param[in] engine signer engine reference
 *
 */
void sock_handle_tcp(sock_type s, void* engine);

#endif /* WIRE_SOCK_H */
