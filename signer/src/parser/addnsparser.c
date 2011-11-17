/*
 * $Id: addnsparser.h 4661 2011-03-25 10:30:29Z matthijs $
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
 * Parsing DNS Adapter.
 *
 */

#include "parser/addnsparser.h"
#include "shared/log.h"

#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <stdlib.h>
#include <string.h>

static const char* parser_str = "parser";

/**
 * Parse the interfaaces.
 *
 */
static acl_type*
parse_addns_acl(allocator_type* allocator, const char* filename, char* expr)
{
    acl_type* acl = NULL;
    acl_type* new_acl = NULL;
    int i = 0;
    char* ipv4 = NULL;
    char* ipv6 = NULL;
    char* port = NULL;
    char* key = NULL;
    xmlDocPtr doc = NULL;
    xmlXPathContextPtr xpathCtx = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode* curNode = NULL;
    xmlChar* xexpr = NULL;

    if (!allocator || !filename || !expr) {
        return NULL;
    }
    /* Load XML document */
    doc = xmlParseFile(filename);
    if (doc == NULL) {
        ods_log_error("[%s] could not parse %s: xmlParseFile() failed",
            parser_str, expr);
        return NULL;
    }
    /* Create xpath evaluation context */
    xpathCtx = xmlXPathNewContext(doc);
    if(xpathCtx == NULL) {
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathNewContext() failed",
            parser_str, expr);
        return NULL;
    }
    /* Evaluate xpath expression */
    xexpr = (xmlChar*) expr;
    xpathObj = xmlXPathEvalExpression(xexpr, xpathCtx);
    if(xpathObj == NULL) {
        xmlXPathFreeContext(xpathCtx);
        xmlFreeDoc(doc);
        ods_log_error("[%s] could not parse %s: xmlXPathEvalExpression() "
            "failed", parser_str, expr);
        return NULL;
    }
    /* Parse interfaces */
    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        for (i = 0; i < xpathObj->nodesetval->nodeNr; i++) {
            ipv4 = NULL;
            ipv6 = NULL;
            port = NULL;
            key = NULL;

            curNode = xpathObj->nodesetval->nodeTab[i]->xmlChildrenNode;
            while (curNode) {
                if (xmlStrEqual(curNode->name, (const xmlChar *)"IPv4")) {
                    ipv4 = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"IPv6")) {
                    ipv6 = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Port")) {
                    port = (char *) xmlNodeGetContent(curNode);
                } else if (xmlStrEqual(curNode->name,
                    (const xmlChar *)"Key")) {
                    key = (char *) xmlNodeGetContent(curNode);
                }
                curNode = curNode->next;
            }
            if (ipv4 || ipv6) {
                new_acl = acl_create(allocator, ipv4, ipv6, port, key);
                if (!new_acl) {
                   ods_log_error("[%s] unable to add %s%s:%s interface: "
                       "acl_push() failed", parser_str, ipv4?ipv4:"",
                       ipv6?ipv6:"", port?port:"");
                } else {
                   new_acl->next = acl;
                   acl = new_acl;
                   ods_log_debug("[%s] added %s%s:%s interface to list %s",
                       parser_str, ipv4?ipv4:"", ipv6?ipv6:"", port?port:"",
                       (char*) expr);
                }
            }
            free((void*)ipv4);
            free((void*)ipv6);
            free((void*)port);
            free((void*)key);
        }
    }
    xmlXPathFreeObject(xpathObj);
    xmlXPathFreeContext(xpathCtx);
    if (doc) {
        xmlFreeDoc(doc);
    }
    return acl;
}


/**
 * Parse <RequestTransfer/>.
 *
 */
acl_type*
parse_addns_request_xfr(allocator_type* allocator, const char* filename)
{
    return parse_addns_acl(allocator, filename,
        "//Adapter/Inbound/RequestTransfer"
        );
}


/**
 * Parse <AllowNotify/>.
 *
 */
acl_type*
parse_addns_allow_notify(allocator_type* allocator, const char* filename)
{
    return parse_addns_acl(allocator, filename,
        "//Adapter/Inbound/AllowNotify"
        );
}


/**
 * Parse <ProvideTransfer/>.
 *
 */
acl_type*
parse_addns_provide_xfr(allocator_type* allocator, const char* filename)
{
    return parse_addns_acl(allocator, filename,
        "//Adapter/Outbound/ProvideTransfer"
        );
}


/**
 * Parse <DoNotify/>.
 *
 */
acl_type*
parse_addns_do_notify(allocator_type* allocator, const char* filename)
{
    return parse_addns_acl(allocator, filename,
        "//Adapter/Outbound/Notify"
        );
}

