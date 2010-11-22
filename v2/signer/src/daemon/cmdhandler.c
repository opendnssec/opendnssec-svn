/*
 * $Id: cmdhandler.c 4134 2010-10-25 10:09:08Z matthijs $
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
 * Command handler.
 *
 */

#include "daemon/cmdhandler.h"
#include "daemon/engine.h"
#include "shared/allocator.h"
#include "shared/file.h"
#include "shared/locks.h"
#include "shared/log.h"

#include <errno.h>
#include <fcntl.h>
#include <ldns/ldns.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#include <unistd.h>
/* According to earlier standards: select() sys/time.h sys/types.h unistd.h */
#include <sys/time.h>
#include <sys/types.h>

#define SE_CMDH_CMDLEN 7

#ifndef SUN_LEN
#define SUN_LEN(su)  (sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

static int count = 0;
static char* cmdh_str = "commandhandler";

/**
 * Handle the 'help' command.
 *
 */
static void
cmdhandler_handle_cmd_help(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "Commands:\n"
        "zones           show the currently known zones\n"
        "sign <zone>     schedule zone for immediate (re-)signing\n"
        "sign --all      schedule all zones for immediate (re-)signing.\n"
        "clear <zone>    delete the internal storage of this zone.\n"
        "                All signatures will be regenerated on the next "
        "re-sign.\n"
        "queue           show the current task queue.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));

    (void) snprintf(buf, ODS_SE_MAXLINE,
        "flush           execute all scheduled tasks immediately.\n"
        "update <zone>   update this zone signer configurations.\n"
        "update [--all]  update zone list and all signer configurations.\n"
        "start           start the engine.\n"
        "reload          reload the engine.\n"
        "stop            stop the engine.\n"
        "verbosity <nr>  set verbosity.\n"
    );
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'update' command.
 *
 */
static void
cmdhandler_handle_cmd_update(int sockfd, cmdhandler_type* cmdc,
    const char* tbd)
{
    char buf[ODS_SE_MAXLINE];
    ods_status status = ODS_STATUS_OK;
    zone_type* zone = NULL;
    task_type* task = NULL;
    task_id what = TASK_SIGN;
    time_t now = 0;
    size_t i = 0;
    int zl_changed = 0;
    int unchanged = 0;
    int updated = 0;
    int errors = 0;

    ods_log_assert(tbd);
    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);

    if (ods_strcmp(tbd, "--all") == 0) {
        /* [LOCK] zonelist */
        lock_basic_lock(&cmdc->engine->zonelist->zl_lock);
        zl_changed = zonelist_update(cmdc->engine->zonelist,
            cmdc->engine->config->zonelist_filename);
        /* [UNLOCK] zonelist */
        if (zl_changed == ODS_STATUS_UNCHANGED) {
            lock_basic_unlock(&cmdc->engine->zonelist->zl_lock);
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list has not changed."
                "\n");
            ods_writen(sockfd, buf, strlen(buf));
        } else if (zl_changed == ODS_STATUS_OK) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list updated: %i "
            "removed, %i added, %i updated.\n",
                cmdc->engine->zonelist->just_removed,
                cmdc->engine->zonelist->just_added,
                cmdc->engine->zonelist->just_updated);
            ods_writen(sockfd, buf, strlen(buf));
            for (i=0; i < ODS_SE_MAXLINE; i++) {
                buf[i] = 0;
            }

            cmdc->engine->zonelist->just_removed = 0;
            cmdc->engine->zonelist->just_added = 0;
            cmdc->engine->zonelist->just_updated = 0;
            lock_basic_unlock(&cmdc->engine->zonelist->zl_lock);

            ods_log_debug("[%s] commit zone list changes", cmdh_str);
            engine_update_zones(cmdc->engine, &unchanged, &updated, &errors);
            ods_log_debug("[%s] signer configurations: %i updated, "
                "%i errors, %i unchanged", cmdh_str, updated, errors,
                unchanged);
            (void)snprintf(buf, ODS_SE_MAXLINE, "Configurations updated: %i "
                "updated, %i errors, %i unchanged.\n", updated, errors,
                unchanged);
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            lock_basic_unlock(&cmdc->engine->zonelist->zl_lock);
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone list has errors.\n");
            ods_writen(sockfd, buf, strlen(buf));
        }
        return;
    } else {
        /* look up zone */
        lock_basic_lock(&cmdc->engine->zonelist->zl_lock);
        /* [LOCK] zonelist */
        zone = zonelist_lookup_zone_by_name(cmdc->engine->zonelist, tbd,
            LDNS_RR_CLASS_IN);
        /* [UNLOCK] zonelist */
        lock_basic_unlock(&cmdc->engine->zonelist->zl_lock);
        if (!zone) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s not found.\n",
                tbd);
            ods_writen(sockfd, buf, strlen(buf));
            return;
        }

        /* if zone exists, load signconf */
        lock_basic_lock(&zone->zone_lock);
        /* [LOCK] zone */
        status = zone_load_signconf(zone, &what);
        if (status == ODS_STATUS_OK) {
            task = (task_type*) zone->task;
            lock_basic_lock(&cmdc->engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            zone->task = schedule_del_task(cmdc->engine->taskq, task);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&cmdc->engine->taskq->schedule_lock);

            now = time_now();
            if (!zone->task) {
                task = task_create(TASK_READ, now, zone->name, zone);
            } else {
                task = zone->task;
                task->what = what;
                task->when = now;
            }
            zone->task = task;

            lock_basic_lock(&cmdc->engine->taskq->schedule_lock);
            /* [LOCK] zone, schedule */
            status = schedule_add_task(cmdc->engine->taskq, zone->task, 0);
            /* [UNLOCK] zone, schedule */
            lock_basic_unlock(&cmdc->engine->taskq->schedule_lock);

            if (status != ODS_STATUS_OK) {
                ods_log_crit("[%s] cannot schedule task for zone %s: %s",
                    cmdh_str, zone->name, ods_status2str(status));
                task_cleanup(task);
                zone->task = NULL;
            }

            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s config updated.\n",
                tbd);
            ods_writen(sockfd, buf, strlen(buf));
        } else if (status == ODS_STATUS_UNCHANGED) {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s config has not "
                "changed.\n", tbd);
            ods_writen(sockfd, buf, strlen(buf));
        } else {
            (void)snprintf(buf, ODS_SE_MAXLINE, "Zone %s signconf has errors."
                "\n", tbd);
            ods_writen(sockfd, buf, strlen(buf));
        }
        lock_basic_unlock(&zone->zone_lock);
        return;
    }
    return;
}


/**
 * Handle the 'zones' command.
 *
 */
static void
cmdhandler_handle_cmd_zones(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];
    size_t i;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    zone_type* zone = NULL;

    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    if (!cmdc->engine->zonelist || !cmdc->engine->zonelist->zones) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no zones configured\n");
        ods_writen(sockfd, buf, strlen(buf));
        return;
    }

    lock_basic_lock(&cmdc->engine->zonelist->zl_lock);
    /* how many zones */
    /* [LOCK] zonelist */
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i zones configured\n",
        (int) cmdc->engine->zonelist->zones->count);
    ods_writen(sockfd, buf, strlen(buf));

    /* list zones */
    node = ldns_rbtree_first(cmdc->engine->zonelist->zones);
    while (node && node != LDNS_RBTREE_NULL) {
        zone = (zone_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)snprintf(buf, ODS_SE_MAXLINE, "- %s\n", zone->name);
        ods_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] zonelist */
    lock_basic_unlock(&cmdc->engine->zonelist->zl_lock);
    return;
}


/**
 * Handle the 'queue' command
 *
 */
static void
cmdhandler_handle_cmd_queue(int sockfd, cmdhandler_type* cmdc)
{
    char* strtime = NULL;
    char buf[ODS_SE_MAXLINE];
    size_t i = 0;
    time_t now = 0;
    ldns_rbnode_t* node = LDNS_RBTREE_NULL;
    task_type* task = NULL;

    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);
    if (!cmdc->engine->taskq || !cmdc->engine->taskq->tasks) {
        (void)snprintf(buf, ODS_SE_MAXLINE, "I have no tasks scheduled.\n");
        ods_writen(sockfd, buf, strlen(buf));
        return;
    }

    lock_basic_lock(&cmdc->engine->taskq->schedule_lock);
    /* [LOCK] schedule */
    /* how many tasks */
    now = time_now();
    strtime = ctime(&now);
    (void)snprintf(buf, ODS_SE_MAXLINE, "I have %i tasks scheduled\nIt is "
        "now %s", (int) cmdc->engine->taskq->tasks->count,
        strtime?strtime:"(null)");
    ods_writen(sockfd, buf, strlen(buf));

    /* list tasks */
    node = ldns_rbtree_first(cmdc->engine->taskq->tasks);
    while (node && node != LDNS_RBTREE_NULL) {
        task = (task_type*) node->data;
        for (i=0; i < ODS_SE_MAXLINE; i++) {
            buf[i] = 0;
        }
        (void)task2str(task, (char*) &buf[0]);
        ods_writen(sockfd, buf, strlen(buf));
        node = ldns_rbtree_next(node);
    }
    /* [UNLOCK] schedule */
    lock_basic_unlock(&cmdc->engine->taskq->schedule_lock);
    return;
}


/**
 * Handle the 'reload' command.
 *
 */
static void
cmdhandler_handle_cmd_reload(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);

    cmdc->engine->need_to_reload = 1;

    lock_basic_lock(&cmdc->engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&cmdc->engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&cmdc->engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, "Reloading engine.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'stop' command.
 *
 */
static void
cmdhandler_handle_cmd_stop(int sockfd, cmdhandler_type* cmdc)
{
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(cmdc);
    ods_log_assert(cmdc->engine);

    cmdc->engine->need_to_exit = 1;

    lock_basic_lock(&cmdc->engine->signal_lock);
    /* [LOCK] signal */
    lock_basic_alarm(&cmdc->engine->signal_cond);
    /* [UNLOCK] signal */
    lock_basic_unlock(&cmdc->engine->signal_lock);

    (void)snprintf(buf, ODS_SE_MAXLINE, ODS_SE_STOP_RESPONSE);
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'start' command.
 *
 */
static void
cmdhandler_handle_cmd_start(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine already running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle the 'running' command.
 *
 */
static void
cmdhandler_handle_cmd_running(int sockfd)
{
    char buf[ODS_SE_MAXLINE];

    (void)snprintf(buf, ODS_SE_MAXLINE, "Engine running.\n");
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle erroneous command.
 *
 */
static void
cmdhandler_handle_cmd_error(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Error: %s.\n", str?str:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle unknown command.
 *
 */
static void
cmdhandler_handle_cmd_unknown(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Unknown command %s.\n",
        str?str:"(null)");
    ods_writen(sockfd, buf, strlen(buf));
    return;
}


/**
 * Handle not implemented.
 *
static void
cmdhandler_handle_cmd_notimpl(int sockfd, const char* str)
{
    char buf[ODS_SE_MAXLINE];
    (void)snprintf(buf, ODS_SE_MAXLINE, "Command %s not implemented.\n", str);
    ods_writen(sockfd, buf, strlen(buf));
    return;
}
 */


/**
 * Handle client command.
 *
 */
static void
cmdhandler_handle_cmd(cmdhandler_type* cmdc)
{
    ssize_t n = 0;
    int sockfd = 0;
    char buf[ODS_SE_MAXLINE];

    ods_log_assert(cmdc);
    sockfd = cmdc->client_fd;

again:
    while ((n = read(sockfd, buf, ODS_SE_MAXLINE)) > 0) {
        buf[n-1] = '\0';
        n--;
        if (n <= 0) {
            return;
        }
        ods_log_verbose("[%s] received command %s[%i]", cmdh_str, buf, n);

        if (n == 4 && strncmp(buf, "help", n) == 0) {
            ods_log_debug("[%s] help command", cmdh_str);
            cmdhandler_handle_cmd_help(sockfd);
        } else if (n == 5 && strncmp(buf, "zones", n) == 0) {
            ods_log_debug("[%s] list zones command", cmdh_str);
            cmdhandler_handle_cmd_zones(sockfd, cmdc);
/*
        } else if (n >= 4 && strncmp(buf, "sign", 4) == 0) {
            ods_log_debug("[%s] sign zone command", cmdh_str);
            if (buf[4] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "sign command needs "
                    "an argument (either '--all' or a zone name)");
            } else if (buf[4] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_sign(sockfd, cmdc, &buf[5]);
            }
        } else if (n >= 5 && strncmp(buf, "clear", 5) == 0) {
            ods_log_debug("[%s] clear zone command", cmdh_str);
            if (buf[5] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "clear command needs "
                    "a zone name");
            } else if (buf[5] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_clear(sockfd, cmdc, &buf[6]);
            }
*/
        } else if (n == 5 && strncmp(buf, "queue", n) == 0) {
            ods_log_debug("[%s] list tasks command", cmdh_str);
            cmdhandler_handle_cmd_queue(sockfd, cmdc);
/*
        } else if (n == 5 && strncmp(buf, "flush", n) == 0) {
            ods_log_debug("[%s] flush tasks command", cmdh_str);
            cmdhandler_handle_cmd_flush(sockfd, cmdc);
*/
        } else if (n >= 6 && strncmp(buf, "update", 6) == 0) {
            ods_log_debug("[%s] update command", cmdh_str);
            if (buf[6] == '\0') {
                cmdhandler_handle_cmd_update(sockfd, cmdc, "--all");
            } else if (buf[6] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_update(sockfd, cmdc, &buf[7]);
            }
        } else if (n == 4 && strncmp(buf, "stop", n) == 0) {
            ods_log_debug("[%s] shutdown command", cmdh_str);
            cmdhandler_handle_cmd_stop(sockfd, cmdc);
            return;
        } else if (n == 5 && strncmp(buf, "start", n) == 0) {
            ods_log_debug("[%s] start command", cmdh_str);
            cmdhandler_handle_cmd_start(sockfd);
        } else if (n == 6 && strncmp(buf, "reload", n) == 0) {
            ods_log_debug("[%s] reload command", cmdh_str);
            cmdhandler_handle_cmd_reload(sockfd, cmdc);
        } else if (n == 7 && strncmp(buf, "running", n) == 0) {
            ods_log_debug("[%s] running command", cmdh_str);
            cmdhandler_handle_cmd_running(sockfd);
/*
        } else if (n >= 9 && strncmp(buf, "verbosity", 9) == 0) {
            ods_log_debug("[%s] verbosity command", cmdh_str);
            if (buf[9] == '\0') {
                cmdhandler_handle_cmd_error(sockfd, "verbosity command "
                    "an argument (verbosity level)");
            } else if (buf[9] != ' ') {
                cmdhandler_handle_cmd_unknown(sockfd, buf);
            } else {
                cmdhandler_handle_cmd_verbosity(sockfd, cmdc, atoi(&buf[10]));
            }
*/
        } else {
            ods_log_debug("[%s] unknown command", cmdh_str);
            cmdhandler_handle_cmd_unknown(sockfd, buf);
        }

        ods_log_debug("[%s] done handling command %s[%i]", cmdh_str, buf, n);
        (void)snprintf(buf, SE_CMDH_CMDLEN, "\ncmd> ");
        ods_writen(sockfd, buf, strlen(buf));
    }

    if (n < 0 && errno == EINTR) {
        goto again;
    } else if (n < 0 && errno == ECONNRESET) {
        ods_log_debug("[%s] done handling client: %s", cmdh_str,
            strerror(errno));
    } else if (n < 0 ) {
        ods_log_error("[%s] read error: %s", cmdh_str, strerror(errno));
    }
    return;
}


/**
 * Accept client.
 *
 */
static void*
cmdhandler_accept_client(void* arg)
{
    cmdhandler_type* cmdc = (cmdhandler_type*) arg;

    ods_thread_blocksigs();
    ods_thread_detach(cmdc->thread_id);

    ods_log_debug("[%s] accept client %i", cmdh_str, cmdc->client_fd);
    cmdhandler_handle_cmd(cmdc);
    if (cmdc->client_fd) {
        close(cmdc->client_fd);
    }
    free(cmdc);
    count--;
    return NULL;
}


/**
 * Create command handler.
 *
 */
cmdhandler_type*
cmdhandler_create(allocator_type* allocator, const char* filename)
{
    cmdhandler_type* cmdh = NULL;
    struct sockaddr_un servaddr;
    int listenfd = 0;
    int flags = 0;
    int ret = 0;

    ods_log_assert(allocator);
    ods_log_assert(filename);
    ods_log_debug("[%s] create socket %s", cmdh_str, filename);

    /* new socket */
    listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listenfd <= 0) {
        ods_log_error("[%s] unable to create, socket() failed: %s", cmdh_str,
            strerror(errno));
        return NULL;
    }
    /* set it to non-blocking */
    flags = fcntl(listenfd, F_GETFL, 0);
    if (flags < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_GETFL) failed: %s",
            cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }
    flags |= O_NONBLOCK;
    if (fcntl(listenfd, F_SETFL, flags) < 0) {
        ods_log_error("[%s] unable to create, fcntl(F_SETFL) failed: %s",
            cmdh_str, strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* no surprises */
    if (filename) {
        unlink(filename);
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;
    strncpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);

    /* bind and listen... */
    ret = bind(listenfd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
    if (ret != 0) {
        ods_log_error("[%s] unable to create, bind() failed: %s", cmdh_str,
            strerror(errno));
        close(listenfd);
        return NULL;
    }
    ret = listen(listenfd, ODS_SE_MAX_HANDLERS);
    if (ret != 0) {
        ods_log_error("[%s] unable to create, listen() failed: %s", cmdh_str,
            strerror(errno));
        close(listenfd);
        return NULL;
    }

    /* all ok */
    cmdh = (cmdhandler_type*) allocator_alloc(allocator,
        sizeof(cmdhandler_type));
    if (!cmdh) {
        close(listenfd);
        return NULL;
    }
    cmdh->listen_fd = listenfd;
    cmdh->listen_addr = servaddr;
    cmdh->need_to_exit = 0;
    return cmdh;
}


/**
 * Start command handler.
 *
 */
void
cmdhandler_start(cmdhandler_type* cmdhandler)
{
    struct sockaddr_un cliaddr;
    socklen_t clilen;
    cmdhandler_type* cmdc = NULL;
    engine_type* engine = NULL;
    fd_set rset;
    int connfd = 0;
    int ret = 0;

    ods_log_assert(cmdhandler);
    ods_log_assert(cmdhandler->engine);
    ods_log_debug("[%s] start", cmdh_str);

    engine = cmdhandler->engine;
    ods_thread_detach(cmdhandler->thread_id);
    FD_ZERO(&rset);
    while (cmdhandler->need_to_exit == 0) {
        clilen = sizeof(cliaddr);
        FD_SET(cmdhandler->listen_fd, &rset);
        ret = select(ODS_SE_MAX_HANDLERS+1, &rset, NULL, NULL, NULL);
        if (ret < 0) {
            if (errno != EINTR && errno != EWOULDBLOCK) {
                ods_log_warning("[%s] select() error: %s", cmdh_str,
                   strerror(errno));
            }
            continue;
        }
        if (FD_ISSET(cmdhandler->listen_fd, &rset)) {
            connfd = accept(cmdhandler->listen_fd,
                (struct sockaddr *) &cliaddr, &clilen);
            if (connfd < 0) {
                if (errno != EINTR && errno != EWOULDBLOCK) {
                    ods_log_warning("[%s] accept error: %s", cmdh_str,
                        strerror(errno));
                }
                continue;
            }
            /* client accepted, create new thread */
            cmdc = (cmdhandler_type*) malloc(sizeof(cmdhandler_type));
            cmdc->listen_fd = cmdhandler->listen_fd;
            cmdc->client_fd = connfd;
            cmdc->listen_addr = cmdhandler->listen_addr;
            cmdc->engine = cmdhandler->engine;
            cmdc->need_to_exit = cmdhandler->need_to_exit;
            ods_thread_create(&cmdc->thread_id, &cmdhandler_accept_client,
                (void*) cmdc);
            count++;
            ods_log_debug("[%s] %i clients in progress...", cmdh_str, count);
        }
    }

    ods_log_debug("[%s] done", cmdh_str);
    engine = cmdhandler->engine;
    engine->cmdhandler_done = 1;
    return;
}
