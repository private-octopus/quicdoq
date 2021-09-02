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
            name_length = name_x - (uint8_t*)name_out;
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
static uint8_t dnscode_test_query0[] = {   1, 255, 1, 0,
    0, 1, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 0,
    0, 0, 41, 8, 0, 0, 0, 0, 0, 0, 0
};

static char const* dnscode_test_query0_json =
"{ \"ID\":511, \"QR\":0, \"Opcode\":0, \"AA\":0,\n\
\"TC\":0, \"RD\":1, \"RA\":0, \"AD\":0, \"CD\":0, \"RCODE\":0,\n\
\"QDCOUNT\":1, \"ANCOUNT\":0, \"NSCOUNT\":0, \"ARCOUNT\":1,\n\
\"QNAME\": \"example.com.\", \"QTYPE\":1, \"QCLASS\":0,\n\
\"additionalRRs\": [\n\
{ \"NAME\": \".\",\n\
\"TYPE\":41, \"CLASS\":2048, \"TTL\":0,\n\
\"RDATAHEX\": \"\"}]}";

static uint8_t dnscode_test_response0[] = {
    0x00, 0x00, 0x80, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x2c, 0x55, 0x00,
    0x04, 0x5d, 0xb8, 0xd8, 0x22 };

static const char* dnscode_test_response0_json = 
"{ \"ID\":0, \"QR\":1, \"Opcode\":0, \"AA\":0,\n\
\"TC\":0, \"RD\":0, \"RA\":1, \"AD\":0, \"CD\":0, \"RCODE\":0,\n\
\"QDCOUNT\":1, \"ANCOUNT\":1, \"NSCOUNT\":0, \"ARCOUNT\":0,\n\
\"QNAME\": \"example.com.\", \"QTYPE\":1, \"QCLASS\":1,\n\
\"answerRRs\": [\n\
{ \"NAME\": \"example.com.\",\n\"TYPE\":1, \"CLASS\":1, \"TTL\":11349,\n\"RDATAHEX\": \"5DB8D822\"}]}";


static uint8_t dnscode_test_response1[] = {
    0x00, 0x00, 0x80, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x07, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
    0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x2c, 0x55, 0x00,
    0x04, 0x5d, 0xb8, 0xd8, 0x22, 0x00, 0x00, 0x29,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const char* dnscode_test_response1_json =
"{ \"ID\":0, \"QR\":1, \"Opcode\":0, \"AA\":0,\n\
\"TC\":0, \"RD\":0, \"RA\":1, \"AD\":0, \"CD\":0, \"RCODE\":0,\n\
\"QDCOUNT\":1, \"ANCOUNT\":1, \"NSCOUNT\":0, \"ARCOUNT\":1,\n\
\"QNAME\": \"example.com.\", \"QTYPE\":1, \"QCLASS\":1,\n\
\"answerRRs\": [\n\
{ \"NAME\": \"example.com.\",\n\"TYPE\":1, \"CLASS\":1, \"TTL\":11349,\n\"RDATAHEX\": \"5DB8D822\"}],\n\
\"additionalRRs\": [\n\
{ \"NAME\": \".\",\n\"TYPE\":41, \"CLASS\":512, \"TTL\":0,\n\"RDATAHEX\": \"\"}]}";

int dns_query_parse_test_one(const uint8_t * query, size_t query_size, char const * query_json)
{
    int ret = 0;
    char query_out[1024];
    size_t query_length = 0;
    size_t next = 0;
    uint8_t* query_x = (uint8_t*)query_out;

    next = quicdoq_parse_dns_query(query, query_size, 0, &query_x,
        (uint8_t*)query_out + sizeof(query_out));
    if (query_x == NULL) {
        ret = -1;
    }
    else {
        query_length = query_x - (uint8_t*)query_out;
        *query_x = 0;

        if (next != query_size) {
            ret = -1;
        }
        else if (strlen(query_json) != query_length) {
            ret = -1;
        }
        else if (memcmp(query_json, query_out, query_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int dns_query_parse_test()
{
    int ret = dns_query_parse_test_one(dnscode_test_query0, sizeof(dnscode_test_query0), dnscode_test_query0_json);

    if (ret == 0) {
        ret = dns_query_parse_test_one(dnscode_test_response0, sizeof(dnscode_test_response0), dnscode_test_response0_json);
    }

    if (ret == 0) {
        ret = dns_query_parse_test_one(dnscode_test_response1, sizeof(dnscode_test_response1), dnscode_test_response1_json);
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

/* Test the RR Type entry */

extern const quicdoq_rr_entry_t rr_table[];
extern const size_t nb_rr_table;

int rr_name_parse_test()
{
    int ret = 0;
    char rr_type_buf[256];
    const uint16_t rr_num[] = { 0, 1, 17, 0xFFFE };
    size_t nb_rr_num = sizeof(rr_num) / sizeof(uint16_t);
    const char* rr_bad[] = { "123x", "x--y" };
    size_t nb_rr_bad = sizeof(rr_bad) / sizeof(const char*);
    uint16_t rr_type;

    for (size_t i = 0; ret == 0 && i < nb_rr_table; i++) {
        memcpy(rr_type_buf, rr_table[i].rr_name, strlen(rr_table[i].rr_name) + 1);
        rr_type = quicdoq_get_rr_type(rr_type_buf);
        if (rr_type != rr_table[i].rr_type) {
            DBG_PRINTF("For %s expected %d, got %d", rr_type_buf, rr_table[i].rr_type, rr_type);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_rr_num; i++) {
        size_t str_len;
        (void)picoquic_sprintf(rr_type_buf, sizeof(rr_type_buf), &str_len, "%d", rr_num[i]);
        rr_type = quicdoq_get_rr_type(rr_type_buf);
        if (rr_type != rr_num[i]) {
            DBG_PRINTF("For %s expected %d, got %d", rr_type_buf, rr_num[i], rr_type);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_rr_bad; i++) {
        rr_type = quicdoq_get_rr_type(rr_bad[i]);
        if (rr_type != UINT16_MAX) {
            DBG_PRINTF("For %s expected %d, got %d", rr_bad[i], UINT16_MAX, rr_type);
            ret = -1;
        }
    }

    return ret;
}

/* Refuse format:
 * Check conditions based on input queries:
 * - bare
 * - extended
 * - multiple
 * - malformed
 * Verify that formatted response is as expected 
 */

static uint8_t dnscode_test_query_bare[] = { 1, 255, 1, 0,
    0, 1, 0, 0, 0, 0, 0, 0,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
};

static uint8_t dnscode_test_query_edns[] = { 1, 255, 1, 0,
    0, 1, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    0, 0, 41, 8, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t dnscode_test_query_multiple[] = { 1, 255, 1, 0,
    0, 2, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    3, 'w', 'w', 'w', 0xc0, 12, 0, 0, 1, 0,
    0, 0, 41, 8, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t dnscode_test_query_bad_format[] = { 1, 255, 1, 0,
    0, 2, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 63, 0, 1, 0, 1,
    0, 0, 41, 8, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t dnscode_test_refuse_bare[] = { 1, 255, 0x81, 5,
    0, 1, 0, 0, 0, 0, 0, 0,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
};

static uint8_t dnscode_test_refuse_edns[] = { 1, 255, 0x81, 5,
    0, 1, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    0, 0, 41, 255, 255, 0, 0, 0, 0, 0, 4, 15, 2, 0, 24
};

static uint8_t dnscode_test_refuse_multiple[] = { 1, 255, 0x81, 5,
    0, 2, 0, 0, 0, 0, 0, 1,
    7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
    3, 'w', 'w', 'w', 0xc0, 12, 0, 0, 1, 0,
    0, 0, 41, 255, 255, 0, 0, 0, 0, 0, 4, 15, 2, 0, 25
};

int refuse_format_test_one(uint8_t* query, size_t query_length, int expected_ret, uint8_t* response, size_t response_length, uint16_t extended_dns_error)
{
    int ret = 0;
    int r_ret;
    uint8_t refused[1024];
    size_t refused_length;

    r_ret = quicdoq_format_refuse_response(query, query_length, refused, sizeof(refused), &refused_length, extended_dns_error);

    if (r_ret != expected_ret) {
        ret = -1;
    }
    else if (r_ret == 0) {
        if (refused_length != response_length) {
            ret = -1;
        }
        else if (memcmp(refused, response, response_length) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int dns_refuse_format_test()
{
    int ret = 0;

    if (ret == 0) {
        ret = refuse_format_test_one(dnscode_test_query_bare, sizeof(dnscode_test_query_bare),
            0, dnscode_test_refuse_bare, sizeof(dnscode_test_refuse_bare), 24);
        if (ret != 0) {
            DBG_PRINTF("%s", "Refused format bare test fails.");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = refuse_format_test_one(dnscode_test_query_edns, sizeof(dnscode_test_query_edns),
            0, dnscode_test_refuse_edns, sizeof(dnscode_test_refuse_edns), 24);
        if (ret != 0) {
            DBG_PRINTF("%s", "Refused format edns test fails.");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = refuse_format_test_one(dnscode_test_query_multiple, sizeof(dnscode_test_query_multiple),
            0, dnscode_test_refuse_multiple, sizeof(dnscode_test_refuse_multiple), 25);
        if (ret != 0) {
            DBG_PRINTF("%s", "Refused format multiple test fails.");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = refuse_format_test_one(dnscode_test_query_bad_format, sizeof(dnscode_test_query_bad_format),
            -1, NULL, 0, 25);
        if (ret != 0) {
            DBG_PRINTF("%s", "Refused format bad_format test fails.");
            ret = -1;
        }
    }

    return ret;
}