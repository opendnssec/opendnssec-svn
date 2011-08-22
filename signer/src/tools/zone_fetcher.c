/*
 * $Id$
 *
 * Copyright (c) 2009 NLnet Labs. All rights reserved.
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
 */

#include "config.h"
#include "shared/log.h"
#include "shared/privdrop.h"
#include "tools/toolutil.h"
#include "tools/zone_fetcher.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/relaxng.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlsave.h>

#define DNS_SERIAL_GT(a, b) ((int)(((a) - (b)) & 0xFFFFFFFF) > 0)

static int sig_quit = 0;
static int sig_reload = 0;

ldns_resolver*
init_xfrd(config_type* config)
{
    serverlist_type* servers;
    ldns_rdf* ns = NULL;
    ldns_status status = LDNS_STATUS_OK;

    ldns_resolver* xfrd = ldns_resolver_new();
    if (config) {
        if (config->use_tsig) {
            ldns_resolver_set_tsig_keyname(xfrd, config->tsig_name);
            if (strncmp(config->tsig_algo, "hmac-md5", 8) == 0) {
                ldns_resolver_set_tsig_algorithm(xfrd, "hmac-md5.sig-alg.reg.int.");
            } else {
                ldns_resolver_set_tsig_algorithm(xfrd, config->tsig_algo);
            }
            ldns_resolver_set_tsig_keydata(xfrd, config->tsig_secret);
        }
        if (config->serverlist && config->serverlist->port)
            ldns_resolver_set_port(xfrd, atoi(config->serverlist->port));
        else
            ldns_resolver_set_port(xfrd, atoi(DNS_PORT_STRING));
        ldns_resolver_set_recursive(xfrd, 0);

        servers = config->serverlist;
        while (servers) {
            if (servers->family == AF_INET6)
                ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, servers->ipaddr);
            else
                ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, servers->ipaddr);
            if (ns) {
                status = ldns_resolver_push_nameserver(xfrd, ns);
                ldns_rdf_deep_free(ns);
                ns = NULL;
            } else {
                ods_log_error("zone fetcher could not use %s for transfer "
                    "request: could not parse ip address", servers->ipaddr);
            }
            if (status != LDNS_STATUS_OK) {
                ods_log_error("zone fetcher could not use %s for transfer "
                    "request: %s", servers->ipaddr,
                    ldns_get_errorstr_by_id(status));
            }
            servers = servers->next;
        }
        if (ldns_resolver_nameserver_count(xfrd) <= 0) {
            ods_log_error("zone fetcher could not find any valid name "
                "servers");
        }

    }
    return xfrd;
}

static zfzonelist_type*
new_zone(char* zone_name, char* input_file)
{
    zfzonelist_type* zlt = (zfzonelist_type*) malloc(sizeof(zfzonelist_type));
    zlt->name = strdup(zone_name);
    zlt->dname = ldns_dname_new_frm_str(zone_name);
    zlt->input_file = strdup(input_file);
    zlt->next = NULL;
    return zlt;
}

static void
free_zonelist(zfzonelist_type* zlt)
{
	zfzonelist_type* next = NULL;

    while (zlt) {
        next = zlt->next;
        free((void*) zlt->name);
        if (zlt->dname) {
            ldns_rdf_deep_free(zlt->dname);
        }
        free((void*) zlt->input_file);
        free((void*) zlt);
        zlt = next;
    }
}

static serverlist_type*
new_server(char* ipv4, char* ipv6, char* port)
{
    serverlist_type* slt = (serverlist_type*) malloc(sizeof(serverlist_type));
    slt->family = AF_UNSPEC;
    if (ipv4) {
        slt->family = AF_INET;
        slt->ipaddr = strdup(ipv4);
    }
    else if (ipv6) {
        slt->family = AF_INET6;
        slt->ipaddr = strdup(ipv6);
    }
    if (port)
        slt->port = strdup(port);
    else
        slt->port = NULL;
    memset(&slt->addr, 0, sizeof(union acl_addr_storage));

    if (slt->family == AF_INET6 && strlen(slt->ipaddr) > 0) {
        if (inet_pton(slt->family, slt->ipaddr, &slt->addr.addr6) != 1) {
            ods_log_error("zone fetcher encountered bad ip address '%s'",
                slt->ipaddr);
        }
    }
    else if (slt->family == AF_INET && strlen(slt->ipaddr) > 0) {
        if (inet_pton(slt->family, slt->ipaddr, &slt->addr.addr) != 1) {
            ods_log_error("zone fetcher encountered bad ip address '%s'",
                slt->ipaddr);
        }
    }

    slt->next = NULL;
    return slt;
}

static void
free_serverlist(serverlist_type* slt)
{
    if (slt) {
        free_serverlist(slt->next);
        if (slt->port)   free((void*) slt->port);
        if (slt->ipaddr) free((void*) slt->ipaddr);
        free((void*) slt);
    }
}

static config_type*
new_config(void)
{
    config_type* cfg = (config_type*) malloc(sizeof(config_type)); /* not freed */
    cfg->use_tsig = 0;
    cfg->pidfile = NULL;
    cfg->tsig_name = NULL;
    cfg->tsig_algo = NULL;
    cfg->tsig_secret = NULL;
    cfg->serverlist = NULL;
    cfg->notifylist = NULL;
    cfg->zonelist_file = NULL;
    cfg->zonelist = NULL;
    return cfg;
}

static void
free_config(config_type* cfg)
{
    if (cfg) {
        if (cfg->tsig_name)   free((void*) cfg->tsig_name);
        if (cfg->tsig_algo)   free((void*) cfg->tsig_algo);
        if (cfg->tsig_secret) free((void*) cfg->tsig_secret);
        if (cfg->pidfile)     free((void*) cfg->pidfile);
        if (cfg->zonelist_file) free((void*) cfg->zonelist_file);
        free_zonelist(cfg->zonelist);
        free_serverlist(cfg->serverlist);
        free_serverlist(cfg->notifylist);
        free((void*) cfg);
    }
}

static int
read_axfr_config(const char* filename, config_type* cfg)
{
    int ret, i, use_tsig = 0;
    char* tag_name, *tsig_name, *tsig_algo, *tsig_secret, *ipv4, *ipv6, *port;
    serverlist_type* serverlist = NULL;
    serverlist_type* notifylist = NULL;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *curNode = NULL;
    xmlChar *tsig_expr = (unsigned char*) "//ZoneFetch/Default/TSIG";
    xmlChar *server_expr = (unsigned char*) "//ZoneFetch/Default/RequestTransfer";
    xmlChar *notify_expr = (unsigned char*) "//ZoneFetch/NotifyListen";

    if (filename == NULL) {
        ods_log_alert("no zone fetcher configfile provided");
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    /* In case zonelist is huge use the XmlTextReader API so that we don't
     * hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename); /* not properly freed */
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <ZoneFetch> */
            if (strncmp(tag_name, "ZoneFetch", 8) == 0 &&
                xmlTextReaderNodeType(reader) == 1) {

                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    ods_log_error("can not read zone fetcher configfile "
                        "%s", filename?filename:"(null)");
                    ods_log_info("zone fetcher exiting...");
                    exit(EXIT_FAILURE);
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    ods_log_error("zone fetcher can not create XPath "
                        "context for %s", filename?filename:"(null)");
                    ods_log_info("zone fetcher exiting...");
                    exit(EXIT_FAILURE);
                }

                /* Extract the master server address */
                xpathObj = xmlXPathEvalExpression(server_expr, xpathCtx);
                if (xpathObj == NULL || !xpathObj->nodesetval) {
                    ods_log_error("zone fetcher can not locate master "
                        "server(s) in %s", filename?filename:"(null)");
                    ods_log_info("zone fetcher exiting...");
                    exit(EXIT_FAILURE);
                }
                else {
                    for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
                        ipv4 = NULL;
                        ipv6 = NULL;
                        port = NULL;
                        curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
                        while (curNode) {
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv4"))
                                ipv4 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv6"))
                                ipv6 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Port"))
                                port = (char *) xmlNodeGetContent(curNode);
                            curNode = curNode->next;
                       }
                       if (ipv4 || ipv6) {
                           if (serverlist == NULL) {
                               serverlist = new_server(ipv4, ipv6, port); /* not freed */
                               cfg->serverlist = serverlist;
                           }
                           else {
                               serverlist->next = new_server(ipv4, ipv6, port); /* not freed */
                               serverlist = serverlist->next;
                           }
                       }

                       if (ipv4) free((void*) ipv4);
                       if (ipv6) free((void*) ipv6);
                       if (port) free((void*) port);
                    }
                    xmlXPathFreeObject(xpathObj);
                }

                /* Extract the notify listen address */
                xpathObj = xmlXPathEvalExpression(notify_expr, xpathCtx);
                if (xpathObj != NULL && xpathObj->nodesetval) {
                    for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
                        ipv4 = NULL;
                        ipv6 = NULL;
                        port = NULL;
                        curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
                        while (curNode) {
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv4"))
                                ipv4 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv6"))
                                ipv6 = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Port"))
                                port = (char *) xmlNodeGetContent(curNode);
                            curNode = curNode->next;
                       }
                       if (ipv4 || ipv6 || port) {
                           if (!ipv4 && !ipv6) {
                               if (notifylist == NULL) {
                                   notifylist = new_server(NULL, "", port);
                                   cfg->notifylist = notifylist;

                                   notifylist->next = new_server("", NULL, port);
                                   notifylist = notifylist->next;
                               }
                               else {
                                   notifylist->next = new_server("", NULL, port);
                                   notifylist = notifylist->next;

                                   notifylist->next = new_server(NULL, "", port);
                                   notifylist = notifylist->next;
                               }
                           }
                           else if (notifylist == NULL) {
                               notifylist = new_server(ipv4, ipv6, port);
                               cfg->notifylist = notifylist;
                           }
                           else {
                               notifylist->next = new_server(ipv4, ipv6, port);
                               notifylist = notifylist->next;
                           }
                       }

                       if (ipv4) free((void*) ipv4);
                       if (ipv6) free((void*) ipv6);
                       if (port) free((void*) port);
                    }
                    xmlXPathFreeObject(xpathObj);
                }

                /* Extract the tsig credentials */
                xpathObj = xmlXPathEvalExpression(tsig_expr, xpathCtx);
                if (xpathObj != NULL && xpathObj->nodesetval) {
                    for (i=0; i < xpathObj->nodesetval->nodeNr; i++) {
                        tsig_name = NULL;
                        tsig_algo = NULL;
                        tsig_secret = NULL;
                        curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
                        while (curNode) {
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Name"))
                                tsig_name = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Algorithm"))
                                tsig_algo = (char *) xmlNodeGetContent(curNode);
                            if (xmlStrEqual(curNode->name, (const xmlChar *)"Secret"))
                                tsig_secret = (char *) xmlNodeGetContent(curNode);
                            curNode = curNode->next;
                       }
                       if (tsig_name && tsig_algo && tsig_secret) {
                           use_tsig = 1;
                           if (cfg->tsig_name) {
                               free((void*) cfg->tsig_name);
                           }
                           if (cfg->tsig_algo) {
                               free((void*) cfg->tsig_algo);
                           }
                           if (cfg->tsig_secret) {
                               free((void*) cfg->tsig_secret);
                           }
                           cfg->tsig_name = strdup(tsig_name);
                           cfg->tsig_algo = strdup(tsig_algo);
                           cfg->tsig_secret = strdup(tsig_secret);
                       }
                       if (tsig_name) {
                           free((void*) tsig_name);
                       }
                       if (tsig_algo) {
                           free((void*) tsig_algo);
                       }
                       if (tsig_secret) {
                           free((void*) tsig_secret);
                       }
                   }
                   xmlXPathFreeObject(xpathObj);
                }
                xmlXPathFreeContext(xpathCtx);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free((void*) tag_name);
        }
        xmlFreeTextReader(reader);
        xmlFreeDoc(doc);
        if (ret != 0) {
            ods_log_error("zone fetcher failed to parse config file %s",
                filename?filename:"(null)");
            ods_log_info("zone fetcher exiting...");
            exit(EXIT_FAILURE);
        }
    } else {
        ods_log_error("zone fetcher was unable to open config file %s",
            filename?filename:"(null)");
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    cfg->use_tsig = use_tsig;
    return 0;
}

static zfzonelist_type*
read_zonelist(const char* filename)
{
    zfzonelist_type* zonelist = NULL, *zonelist_start = NULL;
    char* tag_name, *zone_name, *input_file;
    int ret;

    xmlTextReaderPtr reader = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlChar *name_expr = (unsigned char*) "name";
    xmlChar *adapter_expr = (unsigned char*) "//Zone/Adapters/Input/File";

    if (filename == NULL) {
        ods_log_error("no zonelist provided for zone fetcher");
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    /* In case zonelist is huge use the XmlTextReader API so that we don't hold the whole file in memory */
    reader = xmlNewTextReaderFilename(filename);
    if (reader != NULL) {
        ret = xmlTextReaderRead(reader);
        while (ret == 1) {
            tag_name = (char*) xmlTextReaderLocalName(reader);
            /* Found <Zone> */
            if (strncmp(tag_name, "Zone", 4) == 0 &&
                strncmp(tag_name, "ZoneList", 8) != 0 &&
                xmlTextReaderNodeType(reader) == 1) {
                /* Get the zone name (TODO what if this is null?) */
                zone_name = (char*) xmlTextReaderGetAttribute(reader, name_expr);
                /* Make sure that we got something */
                if (zone_name == NULL) {
                    /* error */
                    ods_log_error("zone fetcher failed to extract zone "
                        "name from %s", filename?filename:"(null)");
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                /* Expand this node and get the rest of the info with XPath */
                xmlTextReaderExpand(reader);
                doc = xmlTextReaderCurrentDoc(reader);
                if (doc == NULL) {
                    ods_log_error("zone fetcher could not read zone "
                        "%s; skipping", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                xpathCtx = xmlXPathNewContext(doc);
                if (xpathCtx == NULL) {
                    ods_log_error("zone fetcher can not create XPath "
                        "context for %s; skipping zone", zone_name);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }

                /* Extract the Input File Adapter filename */
                xpathObj = xmlXPathEvalExpression(adapter_expr, xpathCtx);
                if (xpathObj == NULL || !xpathObj->nodesetval) {
                    ods_log_error("zone fetcher was unable to evaluate "
                        "xpath expression: %s; skipping zone", adapter_expr);
                    /* Don't return? try to parse the rest of the zones? */
                    ret = xmlTextReaderRead(reader);
                    continue;
                }
                input_file = (char*) xmlXPathCastToString(xpathObj);
                xmlXPathFreeObject(xpathObj);

                if (zonelist == NULL) {
                    zonelist = new_zone(zone_name, input_file); /* not freed */
                    zonelist_start = zonelist;
                }
                else {
                    zonelist->next = new_zone(zone_name, input_file);
                    zonelist = zonelist->next;
                }
                free((void*) zone_name);
                free((void*) input_file);

                xmlXPathFreeContext(xpathCtx);
            }

            /* Read the next line */
            ret = xmlTextReaderRead(reader);
            free((void*) tag_name);
        }
        xmlFreeTextReader(reader);
        xmlFreeDoc(doc);
        if (ret != 0) {
            ods_log_error("zone fetcher failed to parse zonelist %s",
                filename?filename:"(null)");
            ods_log_info("zone fetcher exiting...");
            exit(EXIT_FAILURE);
        }
    } else {
        ods_log_error("zone fetcher was unable to open zonelist %s",
            filename?filename:"(null)");
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    return zonelist_start;
}

/** Write pidfile */
static int
writepid(char* pidfile, pid_t pid)
{
    FILE * fd;
    char pidbuf[32];
    size_t result = 0, size = 0;

    snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) pid);
    if ((fd = fopen(pidfile, "w")) ==  NULL ) {
        ods_log_error("zone fetcher could not open pidfile %s for "
            "writing: %s", pidfile?pidfile:"(null)", strerror(errno));
        return -1;
    }
    size = strlen(pidbuf);
    if (size == 0)
        result = 1;
    result = fwrite((const void*) pidbuf, 1, size, fd);
    if (result == 0) {
        ods_log_error("zone fetcher failed to write to pidfile: %s",
            strerror(errno));
    } else if (result < size) {
        ods_log_error("zone fetcher had short write to pidfile "
            "(disk full?)");
        result = 0;
    } else
        result = 1;
    if (!result) {
        ods_log_error("zone fetcher could not write pidfile %s: %s",
            pidfile?pidfile:"(null)", strerror(errno));
        fclose(fd);
        return -1;
    }
    fclose(fd);
    return 0;
}

/** Signal handling. */
static void
sig_handler(int sig)
{
    switch (sig)
    {
        case SIGTERM:
            sig_quit = 1;
            break;
        case SIGHUP:
            sig_reload = 1;
            break;
        default:
            break;
    }
    return;
}

static int
init_sockets(sockets_type* sockets, serverlist_type* list)
{
    int ret = 0, r, ip6_support = 1, on = 0;
    size_t i;
    struct addrinfo hints[MAX_INTERFACES];
    serverlist_type* walk = list;
    serverlist_type* new_list = NULL;
    const char* node = NULL;
    const char* port = NULL;
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
    on = 1;
#endif

    for (i = 0; i < MAX_INTERFACES; i++) {
        memset(&hints[i], 0, sizeof(hints[i]));
        hints[i].ai_family = AF_UNSPEC;
        hints[i].ai_flags = AI_PASSIVE;
        sockets->udp[i].s = -1;
        sockets->tcp[i].s = -1;
    }

    /* if no NotifyListen was provided, we create the default IPv4/IPv6
     * address info structures */
    if (!walk) {
#ifdef  IPV6_V6ONLY
        hints[0].ai_family = AF_INET6;
        hints[1].ai_family = AF_INET;
        new_list = new_server(NULL, "", NULL);
        new_list->next = new_server("", NULL, NULL);
#else   /* !IPV6_V6ONLY */
        hints[0].ai_family = AF_INET6;
        new_list = new_server(NULL, "", NULL);
#endif  /* IPV6_V6ONLY */
        walk = new_list;
    }

    i = 0;
    while (walk) {
        node = strlen(walk->ipaddr) > 0 ? walk->ipaddr : NULL;
        port = walk->port ? walk->port : DNS_PORT_STRING;
        if (node != NULL)
            hints[i].ai_flags |= AI_NUMERICHOST;
        else
            hints[i].ai_family = walk->family;
        /* UDP */
        hints[i].ai_socktype = SOCK_DGRAM;
        /* getaddrinfo */
        if ((r = getaddrinfo(node, port, &hints[i],
            &(sockets->udp[i].addr))) != 0) {
            if (hints[i].ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
                ods_log_error("zone fetcher udp fallback to ipv4, no ipv6: "
                    " not supported");
                ip6_support = 0;
                continue;
            }
            ods_log_error("zone fetcher cannot parse address %s:%s: "
                "getaddrinfo (%i): %s %s", node?node:"(null)",
                port?port:"(null)", walk->family,
                 gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
        }

        /* socket */
        if ((sockets->udp[i].s = socket(sockets->udp[i].addr->ai_family,
            SOCK_DGRAM, 0)) == -1) {
            if (sockets->udp[i].addr->ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
                ods_log_error("zone fetcher udp fallback to ipv4, no ipv6: "
                    " not supported");
                ip6_support = 0;
            }
            else {
                ods_log_error("zone fetcher can't create udp/4 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        }

        if (sockets->udp[i].addr->ai_family == AF_INET) {
            if (fcntl(sockets->udp[i].s, F_SETFL,
                O_NONBLOCK) == -1) {
                ods_log_error("zone fetcher cannot fcntl udp/4 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            if (bind(sockets->udp[i].s,
                (struct sockaddr *) sockets->udp[i].addr->ai_addr,
                sockets->udp[i].addr->ai_addrlen) != 0)
            {
                ods_log_error("zone fetcher can't bind udp/4 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        }
        else if (ip6_support) {
#ifdef IPV6_V6ONLY
#if defined(IPPROTO_IPV6)
            ods_log_verbose("zone fetcher setsockopt ipv6_v6only...");
            if (setsockopt(sockets->udp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                sizeof(on)) < 0)
            {
                ods_log_error("zone fetcher setsockopt(..., IPV6_V6ONLY, "
                "...) failed for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
#endif
#endif /* IPV6_V6ONLY */
            if (fcntl(sockets->udp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                ods_log_error("zone fetcher cannot fcntl udp/6 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            if (bind(sockets->udp[i].s,
                (struct sockaddr *) sockets->udp[i].addr->ai_addr,
                sockets->udp[i].addr->ai_addrlen) != 0) {
                ods_log_error("zone fetcher can't bind udp/6 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        }

        /* TCP */
        hints[i].ai_socktype = SOCK_STREAM;
        /* getaddrinfo */
        if ((r = getaddrinfo(node, port, &hints[i],
            &(sockets->tcp[i].addr))) != 0) {
            if (hints[i].ai_family == AF_INET6 && errno == EAFNOSUPPORT) {
                ods_log_error("zone fetcher tcp fallback to ipv4, no ipv6: "
                    " not supported");
                ip6_support = 0;
                continue;
            }
            ods_log_error("zone fetcher cannot parse address %s:%s: "
                "getaddrinfo (%i): %s %s", node?node:"(null)",
                 port?port:"(null)", walk->family,
                 gai_strerror(r), r==EAI_SYSTEM?strerror(errno):"");
        }
        /* socket */
        if ((sockets->tcp[i].s = socket(sockets->tcp[i].addr->ai_family,
            SOCK_STREAM, 0)) == -1) {
            if (sockets->tcp[i].addr->ai_family == AF_INET6 &&
                errno == EAFNOSUPPORT) {
                ods_log_error("zone fetcher tcp fallback to ipv4, no ipv6: "
                    " not supported");
                ip6_support = 0;
            }
            else {
                ods_log_error("zone fetcher can't create tcp socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        }
        /* setsockopt */
        if (sockets->tcp[i].addr->ai_family == AF_INET) {
            if (setsockopt(sockets->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on,
                sizeof(on)) < 0) {
                ods_log_error("zone fetcher setsockopt(..., SO_REUSEADDR, ...) "
                    "failed for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            /* fcntl */
            if (fcntl(sockets->tcp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                ods_log_error("zone fetcher cannot fcntl tcp/4 for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            /* bind */
            if (bind(sockets->tcp[i].s,
                (struct sockaddr *) sockets->tcp[i].addr->ai_addr,
                sockets->tcp[i].addr->ai_addrlen) != 0) {
                ods_log_error("zone fetcher can't bind tcp/4 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
            /* listen */
           if (listen(sockets->tcp[i].s, 5) == -1) {
                ods_log_error("zone fetcher can't listen to tcp/4 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        } else if (ip6_support) {
            /* setsockopt */
            if (sockets->tcp[i].addr->ai_family == AF_INET6 && ip6_support) {
#ifdef IPV6_V6ONLY
#if defined(IPPROTO_IPV6)
                if (setsockopt(sockets->tcp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on,
                    sizeof(on)) < 0)
                {
                    ods_log_error("zone fetcher setsockopt(..., IPV6_V6ONLY, "
                        "...) failed for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                    ret = -1;
                    break;
                }
#endif
#endif /* IPV6_V6ONLY */
            }
            if (setsockopt(sockets->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on,
                sizeof(on)) < 0) {
                ods_log_error("zone fetcher setsockopt(..., SO_REUSEADDR, ...) "
                    "failed for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            /* fcntl */
            if (fcntl(sockets->tcp[i].s, F_SETFL, O_NONBLOCK) == -1) {
                ods_log_error("zone fetcher cannot fcntl tcp/6 for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
            }
            /* bind */
            if (bind(sockets->tcp[i].s,
                (struct sockaddr *) sockets->tcp[i].addr->ai_addr,
                sockets->tcp[i].addr->ai_addrlen) != 0) {
                ods_log_error("zone fetcher can't bind tcp/6 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
            /* listen */
            if (listen(sockets->tcp[i].s, 5) == -1) {
                ods_log_error("zone fetcher can't listen to tcp/6 socket for "
                    "%s:%s (%s)", node?node:"(null)", port?port:"(null)",
                    strerror(errno));
                ret = -1;
                break;
            }
        }

        walk = walk->next;
        i++;
    }

    if (new_list) {
        free_serverlist(new_list);
    }

    return ret;
}

static void
free_sockets(sockets_type* sockets)
{
    size_t i = 0;

    for (i=0; i < MAX_INTERFACES; i++) {
        if (sockets->udp[i].s != -1) {
            close(sockets->udp[i].s);
            freeaddrinfo((void*)sockets->udp[i].addr);
        }
        if (sockets->tcp[i].s != -1) {
            close(sockets->tcp[i].s);
            freeaddrinfo((void*)sockets->tcp[i].addr);
        }
    }
}

static int
odd_xfer(zfzonelist_type* zone, uint32_t serial, config_type* config, int kick_signer)
{
    ldns_status status = LDNS_STATUS_OK;
    ldns_rr* axfr_rr = NULL, *soa_rr = NULL;
    uint32_t new_serial = 0;
    ldns_pkt* qpkt = NULL, *apkt;
    FILE* fd = NULL;
    char lock_ext[32];
    char axfr_file[MAXPATHLEN];
    char dest_file[MAXPATHLEN];
    char lock_file[MAXPATHLEN];
    char engine_sign_cmd[MAXPATHLEN + 1024];
    int soa_seen = 0;
    ldns_resolver* xfrd = NULL;

    /* soa serial query */
    if (!zone || !zone->dname) {
        ods_log_error("zone fetcher failed to provide a zone for AXFR ");
        return -1;
    }
/* Coverity comment:
   Event deref_ptr: Directly dereferenced pointer "zone"
*/
    qpkt = ldns_pkt_query_new(ldns_rdf_clone(zone->dname),
        LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, LDNS_RD);
    if (!qpkt) {
        ods_log_error("zone fetcher failed to create SOA query. "
            "Aborting AXFR");
        return -1;
    }

    /* Initialise LDNS resolver for AXFR */
    xfrd = init_xfrd(config);

    if (!xfrd) {
        ods_log_error("zone fetcher failed to initialise AXFR structure");
        return -1;
    }

    status = ldns_resolver_send_pkt(&apkt, xfrd, qpkt);
    ldns_pkt_free(qpkt);

    if (status != LDNS_STATUS_OK) {
        ods_log_error("zone fetcher failed to send SOA query: %s",
            ldns_get_errorstr_by_id(status));
        ldns_resolver_deep_free(xfrd);
        return -1;
    }
    if (ldns_pkt_ancount(apkt) == 1) {
        soa_rr = ldns_rr_list_rr(ldns_pkt_answer(apkt), 0);
        if (soa_rr && ldns_rr_get_type(soa_rr) == LDNS_RR_TYPE_SOA) {
            new_serial = ldns_rdf2native_int32(ldns_rr_rdf(soa_rr, 2));
        }
        ldns_pkt_free(apkt);
    } else {
        ods_log_error("zone fetcher saw SOA response with ANCOUNT != 1, "
            "Aborting AXFR");
        /* retry? */
        ldns_pkt_free(apkt);
        ldns_resolver_deep_free(xfrd);
        return -1;
    }

    if (DNS_SERIAL_GT(new_serial, serial)) {
        status = ldns_axfr_start(xfrd, zone->dname, LDNS_RR_CLASS_IN);
        if (status != LDNS_STATUS_OK) {
            ods_log_error("zone fetcher failed to start axfr: %s",
                ldns_get_errorstr_by_id(status));
            ldns_resolver_deep_free(xfrd);
            return -1;
        }

/* Coverity comment:
   Event check_after_deref: Pointer "zone" dereferenced before NULL check
*/
        if (zone && zone->input_file) {
            snprintf(lock_ext, sizeof(lock_ext), "axfr.%lu",
                (unsigned long) getpid());

            snprintf(axfr_file, sizeof(axfr_file), "%s.%s", zone->input_file, lock_ext);
            fd = fopen(axfr_file, "w");
            if (!fd) {
                ods_log_error("zone fetcher cannot store AXFR to file %s", axfr_file);
                ldns_resolver_deep_free(xfrd);
                return -1;
            }
        }
        assert(fd);

        axfr_rr = ldns_axfr_next(xfrd);
        if (!axfr_rr) {
            ods_log_error("zone fetcher AXFR for %s failed",
                zone->name?zone->name:"(null)");
            fclose(fd);
            unlink(axfr_file);
            ldns_resolver_deep_free(xfrd);
            return -1;
        }
        else {
            while (axfr_rr) {
                if (ldns_rr_get_type(axfr_rr) == LDNS_RR_TYPE_SOA) {
                    if (!soa_seen) {
                        soa_seen = 1;
                        ldns_rr_print(fd, axfr_rr);
                    }
                } else {
                    ldns_rr_print(fd, axfr_rr);
                }
                ldns_rr_free(axfr_rr);
                axfr_rr = ldns_axfr_next(xfrd);
            }

            /* RoRi:
             * We MUST now check if the AXFR was successful by verifying that
             * LDNS has seen the SOA record twice. Not doing this can result
             * in a half-transferred zone if the AXFR is interrupted.
             */
             if (!ldns_axfr_complete(xfrd)) {
                 /* The AXFR was not successful, we've received only a partial zone */
                 ods_log_error("zone fetcher AXFR for %s failed, received only a partial zone", zone->name);
                 fclose(fd);
                 unlink(axfr_file);
                 ldns_resolver_deep_free(xfrd);
                 return -1;
             }

            ods_log_info("zone fetcher transferred zone %s serial %u "
                "successfully", zone->name?zone->name:"(null)", new_serial);

            /* Close file before moving it */
            fclose(fd);

            /* moving and kicking */
            snprintf(lock_file, sizeof(lock_file), "%s.lock",
                zone->input_file?zone->input_file:"(null)");

lock_axfr:
            if (access(lock_file, F_OK) == 0) {
                ods_log_deeebug("zone fetcher axfr file %s is locked, "
                    "waiting...", dest_file);
                sleep(1);
                goto lock_axfr;
            } else {
                fd = fopen(lock_file, "w");
                if (!fd) {
                    ods_log_error("zone fetcher cannot lock AXFR file %s",
                        lock_file);
                    ldns_resolver_deep_free(xfrd);
                    return -1;
                }
            }
            assert(fd); /* locked */

            snprintf(dest_file, sizeof(dest_file), "%s.axfr",
                zone->input_file?zone->input_file:"(null)");
            if(rename(axfr_file, dest_file) == 0) {
               fclose(fd);
                (void) unlink(lock_file); /* unlocked */

                if (kick_signer) {
                    snprintf(engine_sign_cmd, sizeof(engine_sign_cmd),
                        "%s sign %s > /dev/null 2>&1",
                        ODS_SE_CLI, zone->name?zone->name:"--all");
                    if (system(engine_sign_cmd) != 0) {
                        ods_log_error("zone fetcher could not kick "
                           "the signer engine to sign zone %s",
                            zone->name?zone->name:"--all");
                    }
                }
            } else {
                fclose(fd);
                (void) unlink(lock_file); /* unlocked */

                ods_log_error("zone fetcher could not move AXFR to %s",
                    dest_file);
            }
            ldns_resolver_deep_free(xfrd);
            return 0;
        }
    } else {
        ods_log_info("zone fetcher zone %s is already up to date, "
            "serial is %u", zone->name?zone->name:"(null)", serial);
    }

    ldns_resolver_deep_free(xfrd);
    return 0;
}

static void
send_udp(uint8_t* buf, size_t len, void* data)
{
    struct handle_udp_userdata *userdata = (struct handle_udp_userdata*)data;
    /* udp send reply */
    ssize_t nb;
    nb = sendto(userdata->udp_sock, buf, len, 0,
        (struct sockaddr*)&userdata->addr_him, userdata->hislen);
    if (nb == -1)
        ods_log_error("zone fetcher sendto() failed: %s", strerror(errno));
    else if ((size_t)nb != len)
        ods_log_error("zone fetcher sendto(): only sent %d of %d octets.",
            (int)nb, (int)len);
}

static void
write_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = send(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            ods_log_error("zone fetcher send() failed: %s",
                strerror(errno));
            return;
        }
        count += nb;
    }
}

static void
send_tcp(uint8_t* buf, size_t len, void* data)
{
    struct handle_tcp_userdata *userdata = (struct handle_tcp_userdata*)data;
    uint16_t tcplen;
    /* tcp send reply */
    tcplen = htons(len);
    write_n_bytes(userdata->s, (uint8_t*)&tcplen, sizeof(tcplen));
    write_n_bytes(userdata->s, buf, len);
}

static void
handle_query(uint8_t* inbuf, ssize_t inlen,
    void (*sendfunc)(uint8_t*, size_t, void*),
    void* userdata, config_type* config)
{
    zfzonelist_type* zonelist = NULL;
    ldns_status status = LDNS_STATUS_OK;
    ldns_pkt *query_pkt = NULL;
    ldns_rr *query_rr = NULL;
    uint32_t serial = 0;
    char* owner_name = NULL;
    uint8_t *outbuf = NULL;
    size_t answer_size = 0;
    char dest_file[MAXPATHLEN];
    FILE* fd;

    /* packet parsing */
    status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)inlen);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("zone fetcher got bad packet: %s",
            ldns_get_errorstr_by_id(status));
        return;
    }
    query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);

    if (ldns_pkt_get_opcode(query_pkt) != LDNS_PACKET_NOTIFY ||
        ldns_pkt_get_rcode(query_pkt)  != LDNS_RCODE_NOERROR ||
        ldns_pkt_qr(query_pkt) ||
        !ldns_pkt_aa(query_pkt) ||
        ldns_pkt_tc(query_pkt) ||
        ldns_pkt_rd(query_pkt) ||
        ldns_pkt_ra(query_pkt) ||
        ldns_pkt_cd(query_pkt) ||
        ldns_pkt_ad(query_pkt) ||
        ldns_pkt_qdcount(query_pkt) != 1 ||
        ldns_pkt_nscount(query_pkt) != 0 ||
        ldns_pkt_arcount(query_pkt) != 0 ||
        ldns_rr_get_type(query_rr) != LDNS_RR_TYPE_SOA ||
        ldns_rr_get_class(query_rr) != LDNS_RR_CLASS_IN)
    {
        ods_log_info("zone fetcher drop bad notify");
        return;
    }

    /* NOTIFY OK */
    if (config) {
        zonelist = config->zonelist;
    }
    ldns_pkt_set_qr(query_pkt, 1);
    status = ldns_pkt2wire(&outbuf, query_pkt, &answer_size);
    if (status != LDNS_STATUS_OK) {
        ods_log_error("zone fetcher error creating notify response: %s",
            ldns_get_errorstr_by_id(status));
    }
    sendfunc(outbuf, answer_size, userdata);
    LDNS_FREE(outbuf);

    /* send AXFR request */
    while (zonelist) {
        if (ldns_dname_compare(ldns_rr_owner(query_rr), zonelist->dname) == 0)
        {
            ods_log_info("zone fetcher received NOTIFY for zone %s",
                zonelist->name?zonelist->name:"(null)");
            /* get latest serial */
            snprintf(dest_file, sizeof(dest_file), "%s.axfr",
                zonelist->input_file?zonelist->input_file:"(null)");
            fd = fopen(dest_file, "r");
            if (!fd) {
                serial = 0;
            } else {
                serial = lookup_serial(fd);
                fclose(fd);
            }
            if (odd_xfer(zonelist, serial, config, 1) != 0) {
                ods_log_error("AXFR for zone %s failed",
                    zonelist->name?zonelist->name:"(null)");
            }
            ldns_pkt_free(query_pkt);
            return;
        }
        /* next */
        zonelist = zonelist->next;
    }
    owner_name = ldns_rdf2str(ldns_rr_owner(query_rr));
    ods_log_warning("zone fetcher notify received for unknown zone: %s",
        owner_name?owner_name:"(null)");
    free((void*)owner_name);
    ldns_pkt_free(query_pkt);
}

static void
read_n_bytes(int sock, uint8_t* buf, size_t sz)
{
    size_t count = 0;
    while(count < sz) {
        ssize_t nb = recv(sock, buf+count, sz-count, 0);
        if(nb < 0) {
            ods_log_error("zone fetcher recv() failed: %s",
                strerror(errno));
            return;
        }
        count += nb;
    }
}

static char*
addr2ip(struct sockaddr_storage addr, char* remote, size_t len)
{
    if (addr.ss_family == AF_INET6) {
        if (!inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&addr)->sin6_addr,
            remote, len)) {
            return NULL;
        }
    } else {
        if (!inet_ntop(AF_INET, &((struct sockaddr_in *)&addr)->sin_addr,
            remote, len))
            return NULL;
    }

    return remote;
}

static int
acl_matches(struct sockaddr_storage* addr, config_type* config)
{
    serverlist_type* serverlist = NULL;

    if (config && config->serverlist) {
        serverlist = config->serverlist;
        while (serverlist) {
            if (serverlist->family == AF_INET6) {
                struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
                if (serverlist->family == addr->ss_family &&
                    memcmp(&addr6->sin6_addr, &serverlist->addr.addr6,
                     sizeof(struct in6_addr)) == 0)
                {
                    return 1;
                }
            }
           else {
                struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
                if (serverlist->family == addr4->sin_family &&
                    memcmp(&addr4->sin_addr, &serverlist->addr.addr,
                     sizeof(struct in_addr)) == 0)
                {
                    return 1;
                }
            }

            serverlist = serverlist->next;
        }
    }
    return 0;
}

static void
handle_udp(int udp_sock, config_type* config)
{
    ssize_t nb;
    uint8_t inbuf[INBUF_SIZE];
    struct handle_udp_userdata userdata;
    char* remote;

    userdata.udp_sock = udp_sock;
    userdata.hislen = (socklen_t) sizeof(userdata.addr_him);
    nb = recvfrom(udp_sock, inbuf, INBUF_SIZE, 0,
        (struct sockaddr*) &userdata.addr_him, &userdata.hislen);
    if (nb < 1) {
        ods_log_error("zone fetcher recvfrom() failed: %s",
            strerror(errno));
        return;
    }

    /* acl */
    if (!acl_matches(&userdata.addr_him, config)) {
        remote = (char*) malloc(sizeof(char)*userdata.hislen);
        ods_log_warning("zone fetcher refused message from "
            "unauthoritative source: %s",
            addr2ip(userdata.addr_him, remote, userdata.hislen));
        free((void*)remote);
        return;
    }
    handle_query(inbuf, nb, send_udp, &userdata, config);
}

static void
handle_tcp(int tcp_sock, config_type* config)
{
    int s;
    struct sockaddr_storage addr_him;
    socklen_t hislen;
    uint8_t inbuf[INBUF_SIZE];
    uint16_t tcplen;
    struct handle_tcp_userdata userdata;
    char* remote;

    /* accept */
    hislen = (socklen_t)sizeof(addr_him);
    if((s = accept(tcp_sock, (struct sockaddr*)&addr_him, &hislen)) < 0) {
        ods_log_error("zone fetcher accept() failed: %s", strerror(errno));
        return;
    }
    userdata.s = s;

    /* tcp recv */
    read_n_bytes(s, (uint8_t*)&tcplen, sizeof(tcplen));
    tcplen = ntohs(tcplen);
    if(tcplen >= INBUF_SIZE) {
        ods_log_error("zone fetcher query %d bytes too large, "
            "buffer %d bytes.", tcplen, INBUF_SIZE);
        close(s);
        return;
    }
    read_n_bytes(s, inbuf, tcplen);

    /* acl */
    if (!acl_matches(&addr_him, config)) {
        remote = (char*) malloc(sizeof(char)*hislen);
        ods_log_warning("zone fetcher refused message from "
            "unauthoritative source: %s",
            addr2ip(addr_him, remote, hislen));
        free((void*)remote);
        close(s);
        return;
    }
    handle_query(inbuf, (ssize_t) tcplen, send_tcp, &userdata, config);
    close(s);
}


/**
 * Reload the zonelist file and merge it with the existing configuration.
 *
 */
static void
reload_zonelist(config_type *config) {
    zfzonelist_type *new_zonelist, **thisp;
    zfzonelist_type *added_zonelist = NULL, *kept_zonelist = NULL;
    int added_count = 0, changed_count = 0, kept_count = 0;
    /* Fail softly if the zonelist cannot be accessed for reloading */
    if (!config->zonelist_file) {
	    ods_log_error("zone fetcher is unable to access the zonelist");
	    return;
    } else {
	    ods_log_verbose("zone fetcher will reload the zonelist");
    }
    /* Read the zonelist file and construct a new linked list of zonelist entries */
    new_zonelist = read_zonelist (config->zonelist_file);
    /* Iterate over the new zonelist file and compare it to previously configured zonelist entries */
    while (new_zonelist) {
	    zfzonelist_type *next_zonelist = new_zonelist->next;
	    zfzonelist_type *this = config->zonelist;
	    int found = 0;
	    while (this && !found) {
	        found = !strcmp (this->name, new_zonelist->name);
	        if (!found) {
		        this = this->next;
            }
    	}

    	/* If the zone name is found in the old zonelist, it is either a full match or a replacement */
	    if (found) {
	        if (strcmp (new_zonelist->input_file, this->input_file)) {
		    /* the zonelist entry has changed -- treat as a replacement/new zonelist entry */
		    changed_count++;
		    new_zonelist->next = added_zonelist;
		    added_zonelist = new_zonelist;
    	    } else {
	    	/* the zonelist entry is already configured -- treat as a kept zonelist entry */
		    kept_count++;
		    new_zonelist->next = kept_zonelist;
		    kept_zonelist = new_zonelist;
	        }
	    } else {
	        /* new_zonelist introduces a new zonelist entry */
	        added_count++;
	        new_zonelist->next = added_zonelist;
	        added_zonelist = new_zonelist;
    	}
	    new_zonelist = next_zonelist;
    }

    /* Replace the configured zonelist with the added_zonelist and kept_zonelist */
    free_zonelist (config->zonelist);
    config->zonelist = kept_zonelist;
    thisp = &config->zonelist;
    while (*thisp) {
    	thisp = &(*thisp)->next;
    }
    *thisp = added_zonelist;

    /* Perform an initial AXFR for the newly added zones (assume no present inputfile) */
    new_zonelist = added_zonelist;
    while (new_zonelist) {
    	/* send the request -- assume no file is present so SOA is 0 */
	    if (odd_xfer (new_zonelist, 0, config, 1) != 0) {
	        ods_log_error("AXFR for new zone %s failed", new_zonelist->name);
	    }
	    /* next */
	    new_zonelist = new_zonelist->next;
    }
    ods_log_verbose("Reloaded zonelist -- kept %d, changed %d and added %d zones",
		kept_count, changed_count, added_count);
    return;
}


static void
xfrd_ns(sockets_type* sockets, config_type* cfg)
{
    fd_set rset, wset, eset;
    struct timeval timeout;
    int count, maxfd = 0;
    size_t i;

    /* service */
    count = 0;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    while (!sig_quit) {
        if (sig_reload) {
            reload_zonelist(cfg);
            sig_reload = 0;
        }
        FD_ZERO(&rset);
        FD_ZERO(&wset);
        FD_ZERO(&eset);
        for (i=0; i < MAX_INTERFACES; i++) {
            if (sockets->udp[i].s != -1)
                FD_SET(sockets->udp[i].s, &rset);
            if (sockets->tcp[i].s != -1)
                FD_SET(sockets->tcp[i].s, &rset);
            if (sockets->udp[i].s > maxfd) maxfd = sockets->udp[i].s;
            if (sockets->tcp[i].s > maxfd) maxfd = sockets->tcp[i].s;
        }

        if (select(maxfd+1, &rset, &wset, &eset, NULL) < 0) {
            if (errno == EINTR)
                continue;
            ods_log_error("zone fetcher select(): %s", strerror(errno));
        }

        for (i=0; i < MAX_INTERFACES; i++) {
            if (sockets->udp[i].s != -1 && FD_ISSET(sockets->udp[i].s, &rset))
                handle_udp(sockets->udp[i].s, cfg);
            if (sockets->tcp[i].s != -1 && FD_ISSET(sockets->tcp[i].s, &rset))
                handle_tcp(sockets->tcp[i].s, cfg);
        }
    }
}

static void
list_settings(FILE* out, config_type* config, const char* filename)
{
    zfzonelist_type* zones = NULL;
    serverlist_type* servers = NULL;

    if (config) {
        fprintf(out, "configuration settings:\n");
        fprintf(out, "filename: %s\n", filename?filename:"(null)");
        fprintf(out, "pidfile: %s\n",
            config->pidfile?config->pidfile:"(null)");
        fprintf(out, "tsig: %s\n", config->use_tsig?"yes":"no");
        if (config->use_tsig) {
            fprintf(out, "tsig name: %s\n",
                config->tsig_name?config->tsig_name:"(null)");
            fprintf(out, "tsig algorithm: %s\n",
                config->tsig_algo?config->tsig_algo:"(null)");
            fprintf(out, "tsig secret: ?\n");
        }
        fprintf(out, "zones: %s\n", config->zonelist?"":"none");
        zones = config->zonelist;
        while (zones) {
            fprintf(out, "\t%s\n", zones->name?zones->name:"(null)");
            zones = zones->next;
        }
        fprintf(out, "master servers: %s\n", config->serverlist?"":"none");
        servers = config->serverlist;
        while (servers) {
            fprintf(out, "\t%s\n", servers->ipaddr?servers->ipaddr:"(null)");
            servers = servers->next;
        }
        fprintf(out, "interfaces: %s\n", config->notifylist?"":"none");
        servers = config->notifylist;
        while (servers) {
            fprintf(out, "\t%s %s:%s\n",
                servers->family==AF_INET6?"ipv6":"ipv4",
                servers->ipaddr?servers->ipaddr:"(null)",
                servers->port?servers->port:"(null)");
            servers = servers->next;
        }
        fprintf(out, "list zone fetcher settings done.\n");
    }
    else fprintf(out, "no config\n");
}

int
tools_zone_fetcher(const char* config_file, const char* zonelist_file,
    const char* group, const char* user, const char* chroot, const char* log_file,
    int use_syslog, int verbosity)
{
    zfzonelist_type *zonelist = NULL;
    config_type* config = NULL;
    uint32_t serial = 0;
    FILE* fd;
    sockets_type sockets;
    int c, info = 0;
    int error = 0;
    struct sigaction action;
    uid_t uid = -1;
    gid_t gid = -1;

    ods_log_init(log_file, use_syslog, verbosity);

    /* read transfer configuration */
    config = new_config();
    config->pidfile = strdup(ODS_ZF_PIDFILE); /* not freed */
    if (!config->pidfile) {
        ods_log_alert("zone fetcher error: no pidfile given");
        free_config(config);
        exit(EXIT_FAILURE);
    }

    c = read_axfr_config(config_file, config);
    config->zonelist = read_zonelist(zonelist_file);
    config->zonelist_file = strdup(zonelist_file);

    if (info) {
        list_settings(stdout, config, config_file);
    }

    if (config->serverlist == NULL) {
        ods_log_alert("zone fetcher error: no master servers configured "
            "with <RequestTransfer>");
        free_config(config);
        exit(EXIT_FAILURE);
    }

    /* setup signal handing */
    action.sa_handler = sig_handler;
    sigfillset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    /* write pidfile */
    if (writepid(config->pidfile, getpid()) != 0) {
        ods_log_error("write pidfile %s failed", config->pidfile);
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    ods_log_info("zone fetcher started");

    /* foreach zone, do a single axfr request */
    zonelist = config->zonelist;
    while (zonelist != NULL) {
        /* get latest serial */
        fd = fopen(zonelist->input_file, "r");
        if (!fd) {
            serial = 0;
        } else {
            serial = lookup_serial(fd);
            fclose(fd);
        }
        /* send the request */
        if (odd_xfer(zonelist, serial, config, 1) != 0) {
            ods_log_error("AXFR for zone %s failed",
                zonelist->name?zonelist->name:"(null)");
        }
        /* next */
        zonelist = zonelist->next;
    }

    /* listen to NOTIFY messages */
    c = init_sockets(&sockets, config->notifylist);
    if (c == -1) {
        ods_log_error("zone fetcher failed to initialize sockets");
        if (unlink(config->pidfile) == -1) {
            ods_log_error("unlink pidfile %s failed: %s",
                config->pidfile?config->pidfile:"(null)",
                strerror(errno));
        }
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    /* drop privileges */
    error = privdrop(user, group, chroot, &uid, &gid);
    privclose(user, group);
    if (error != 0) {
        ods_log_error("zone fetcher failed to drop privileges");
        if (unlink(config->pidfile) == -1) {
            ods_log_error("unlink pidfile %s failed: %s",
                config->pidfile?config->pidfile:"(null)",
                strerror(errno));
        }
        free_sockets(&sockets);
        ods_log_info("zone fetcher exiting...");
        exit(EXIT_FAILURE);
    }

    xfrd_ns(&sockets, config);

    if (unlink(config->pidfile) == -1) {
        ods_log_warning("unlink pidfile %s failed: %s",
            config->pidfile?config->pidfile:"(null)",
            strerror(errno));
    }
    free_sockets(&sockets);

    /* done */
    ods_log_debug("zone fetcher done");
    free_config(config);
    ods_log_close();
    return 0;
}
