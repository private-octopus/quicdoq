/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include "quicdoq.h"
#include "quicdoq_internal.h"

static uint8_t dnscode_test1[] = { 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test2[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '-', '2', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test3[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '_', '3', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test4[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', ':', '4', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test5[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', '5', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test6[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x7F, '6', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test7[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', ' ', '7', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test8[] = { 10, ' ', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '-', '8', 3, 'c', 'o', 'm', 0 };
static uint8_t dnscode_test9[] = { 9, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '-', '9', 3, 0x8c, 0xFF, 0x81, 0 };

static struct st_dnscode_testLine {
    uint8_t* dns;
    size_t dns_length;
    char const* expected;
} dnscode_testData[] = {
    { dnscode_test1, sizeof(dnscode_test1), "example.com." },
    { dnscode_test2, sizeof(dnscode_test2), "example-2.com." },
    { dnscode_test3, sizeof(dnscode_test3), "example_3.com." },
    { dnscode_test4, sizeof(dnscode_test4), "example:4.com." },
    { dnscode_test5, sizeof(dnscode_test5), "example\\0465.com." },
    { dnscode_test6, sizeof(dnscode_test6), "example\\1276.com." },
    { dnscode_test7, sizeof(dnscode_test7), "example 7.com." },
    { dnscode_test8, sizeof(dnscode_test8), "\\032example-8.com." },
    { dnscode_test9, sizeof(dnscode_test9), "example-9.\\140\\255\\129." }
};


/* Test the DNS parsing function */
int name_parse_test()
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < sizeof(dnscode_testData) / sizeof(struct st_dnscode_testLine); i++) {
        char name_out[1024];
        size_t name_length = 0;
        size_t next = 0;
        uint8_t* name_x = (uint8_t*)name_out;

        next = quicdoq_parse_dns_name(dnscode_testData[i].dns, dnscode_testData[i].dns_length, 0, &name_x,
            (uint8_t*)name_out + sizeof(name_out));
        if (name_x == NULL) {
            ret = -1;
        } else {
            name_length = name_x - name_out;
            *name_x = 0;
        }

        if (next != dnscode_testData[i].dns_length) {
            ret = -1;
        } else if (strlen(dnscode_testData[i].expected) != name_length) {
            ret = -1;
        } else if (memcmp(dnscode_testData[i].expected, name_out, name_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}

/* Test the DNS formatting function */
int name_format_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < sizeof(dnscode_testData) / sizeof(struct st_dnscode_testLine); i++) {
        uint8_t dns_name[1024];
        uint8_t * next = dns_name;
        size_t dns_length = 0;

        next = quicdog_format_dns_name(next, next + sizeof(dns_name), dnscode_testData[i].expected);

        if (next == NULL) {
            ret = -1;
        }
        else {
            dns_length = next - dns_name;
        }
        
        if (dnscode_testData[i].dns_length != dns_length) {
            ret = -1;
        }
        else if (memcmp(dnscode_testData[i].dns, dns_name, dns_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}

/* Test the query formatting function */
static uint8_t dnscode_test_query0[] = {   1, 255, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 0,
    0, 0, 41, 8, 0, 0, 0, 0, 0, 0, 0
};

static char const* dnscode_test_query0_json =
"{ \"ID\":511, \"QR\":0, \"Opcode\":0, \"AA\":0,\n\
\"TC\":0, \"RD\":0, \"AD\":0, \"CD\":0, \"RCODE\":0,\n\
\"QDCOUNT\":1, \"ANCOUNT\":0, \"NSCOUNT\":0, \"ARCOUNT\":1,\n\
\"QNAME\": \"example.com.\", \"QTYPE\":1, \"QCLASS\":0,\n\
\"additionalRRs\": [\n\
{ \"NAME\": \".\",\n\
\"TYPE\":41, \"CLASS\":2048, \"TTL\":0,\n\
\"RDATAHEX\": \"\"}]}";

int dns_query_parse_test()
{
    int ret = 0;
    char query_out[1024];
    size_t query_length = 0;
    size_t next = 0;
    uint8_t* query_x = (uint8_t*)query_out;

    next = quicdoq_parse_dns_query(dnscode_test_query0, sizeof(dnscode_test_query0), 0, &query_x,
        (uint8_t*)query_out + sizeof(query_out));
    if (query_x == NULL) {
        ret = -1;
    }
    else {
        query_length = query_x - query_out;
        *query_x = 0;

        if (next != sizeof(dnscode_test_query0)) {
            ret = -1;
        }
        else if (strlen(dnscode_test_query0_json) != query_length) {
            ret = -1;
        }
        else if (memcmp(dnscode_test_query0_json, query_out, query_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int dns_query_format_test()
{
    int ret = 0;
    uint8_t dns_query[1024];
    uint8_t* next = dns_query;
    size_t query_length = 0;

    next = quicdog_format_dns_query(next, next + sizeof(dns_query), "example.com.", 511, 0, 1, 2048);

    if (next == NULL) {
        ret = -1;
    }
    else {
        query_length = next - dns_query;

        if (sizeof(dnscode_test_query0) != query_length) {
            ret = -1;
        }
        else if (memcmp(dnscode_test_query0, dns_query, query_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}