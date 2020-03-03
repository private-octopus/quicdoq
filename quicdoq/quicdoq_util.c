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
#include <stdarg.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include "quicdoq.h"
#include "quicdoq_internal.h"

/* Utilities for text handling
*/
uint8_t* quicdoq_add_char(uint8_t* text, uint8_t* text_max, uint8_t c)
{
    if (text != NULL && text + 1 < text_max) {
        *text++ = c;
    }
    else {
        text = NULL;
    }
    return text;
}

uint8_t* quicdoq_add_string(uint8_t* text, uint8_t* text_max, char const * s, size_t l)
{
    if (text != NULL && text + l < text_max) {
        memcpy(text, s, l);
        text += l;
    }
    else {
        text = NULL;
    }
    return text;
}

uint8_t* quicdoq_add_label(uint8_t* text, uint8_t* text_max, char const* s, size_t l)
{
    if (text != NULL && text + l + 2 < text_max) {
        *text++ = '"';
        memcpy(text, s, l);
        text += l;
        *text++ = '"';
    }
    else {
        text = NULL;
    }
    return text;
}

uint8_t* quicdoq_sprintf(uint8_t* text, uint8_t* text_max, const char* fmt, ...)
{
    if (text != NULL) {
        size_t buf_len = text_max - text;
        va_list args;
        va_start(args, fmt);
#ifdef _WINDOWS
        int res = vsnprintf_s((char*)text, buf_len, _TRUNCATE, fmt, args);
#else
        int res = vsnprintf((char*)text, buf_len, fmt, args);
#endif
        va_end(args);

        if (res < 0 || (unsigned) res > buf_len) {
            text = NULL;
        }
        else {
            text += res;
        }
    }

    return text;
}

uint8_t* quicdoq_add_label_num(uint8_t* text, uint8_t* text_max, char const* s,int v)
{
    return quicdoq_sprintf(text, text_max, "\"%s\":%d", s, v);
}

uint8_t* quicdoq_add_hex(uint8_t* text, uint8_t* text_max, const uint8_t* data, size_t ldata)
{
    for (size_t i = 0; text != NULL && i < ldata; i++) {
        if (text + 2 > text_max) {
            text = NULL;
        }
        else {
            int hex[2];
            hex[0] = data[i] >> 4;
            hex[1] = data[i] & 0x0F;

            for (int j = 0; j < 2; j++) {
                if (hex[j] < 10) {
                    *text++ = (uint8_t)('0' + hex[j]);
                }
                else {
                    *text++ = (uint8_t)('A' - 10 + hex[j]);
                }
            }
        }
    }

    return text;
}

uint8_t * NormalizeNamePart(size_t length, const uint8_t* value,
    uint8_t* normalized, uint8_t * normalized_max)
{
    if (normalized != NULL) {
        for (uint32_t i = 0; i < length ; i++)
        {
            uint8_t c = value[i];
            unsigned int need_escape = 1;


            if (normalized + 1 >= normalized_max) {
                normalized = NULL;
                break;
            }
            else {

                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c == '-' || c == '_'))
                {
                    need_escape = 0;
                }
                else if (c == 127 || c < ' ' || c > 127) {
                    need_escape = 1;
                }
                else if (c == ' ')
                {
                    need_escape = (i == 0 || i == (length - 1));
                }
                else
                {
                    need_escape = (c == '.');
                }
                if (need_escape) {
                    if (normalized + 4 < normalized_max) {
                        int dec[3];
                        dec[0] = c / 100;
                        dec[1] = (c % 100) / 10;
                        dec[2] = c % 10;

                        *normalized++ = '\\';
                        for (int x = 0; x < 3; x++) {
                            *normalized++ = (uint8_t)('0' + dec[x]);
                        }
                    }
                    else {
                        normalized = NULL;
                        break;
                    }
                }
                else {
                    *normalized++ = c;
                }
            }
        }
    }
    if (normalized != NULL) {
        *normalized = 0;
    }

    return normalized;
}

/* Create a DNS Request from name and type.
 * This can be used for tests and also for the demo application.
 */
uint8_t* quicdog_format_dns_name(uint8_t* data, uint8_t* data_max, char const* name)
{
    size_t l = 0;
    uint8_t* part_data;
    while (data != NULL && name[l] != 0) {
        part_data = data++;
        while (data != NULL && name[l] != 0) {
            uint8_t c = name[l++];

            if (c == '.') {
                break;
            }
            else if (data + 1 >= data_max) {
                data = NULL;
                break;
            }

            if (c == '\\') {
                uint8_t cx = 0;

                for (int i = 0; data != NULL && i < 3; i++) {
                    int p = name[l++];
                    if (p == 0) {
                        data = NULL;
                        break;
                    }
                    else if (p >= '0' && p <= '9') {
                        cx *= 10;
                        cx += (uint8_t)(p - '0');
                    }
                }
                c = cx;
            }
            if (data != NULL) {
                *data++ = c;
            }
        }

        if (data != NULL) {
            if (part_data + 1 >= data) {
                /* NULL name part */
                if (name[l] != 0) {
                    data = NULL;
                }
                break;
            }
            else {
                *part_data = (uint8_t)(data - part_data - 1);
            }
        }
    }
    if (data != NULL) {
        if (data + 1 >= data_max) {
            data = NULL;
        }
        else {
            *data++ = 0;
        }
    }
    return data;
}

uint8_t* quicdog_format_dns_query(uint8_t* data, uint8_t* data_max, char const* qname, uint16_t id, uint16_t qclass, uint16_t qtype, uint16_t l_max)
{
    if (data_max - data < 12) {
        data = NULL;
    }
    else {
        /* basic query header */
        *data++ = (uint8_t)(id >> 8);
        *data++ = (uint8_t)(id & 255);
        *data++ = 0; /* QR = 0, opcode = 0; AA,TC,RD = 0*/
        *data++ = 0; /* RA,AD,CD=0, rcode=0 */
        *data++ = 0; *data++ = 1; /* qdcount = 0*/
        *data++ = 0; *data++ = 0; /* ancount = 0*/
        *data++ = 0; *data++ = 0; /* nscount = 0*/
        *data++ = 0; *data++ = 1; /* adcount = 1, edns */
    }
    /* Encode the query itself */
    data = quicdog_format_dns_name(data, data_max, qname);
    if (data != NULL) {
        if (data + 4 < data_max) {
            *data++ = (uint8_t)(qtype >> 8);
            *data++ = (uint8_t)(qtype & 255);
            *data++ = (uint8_t)(qclass >> 8);
            *data++ = (uint8_t)(qclass & 255);
        }
        else {
            data = NULL;
        }
    }
    /* Encode the EDNS record */
    if (data != NULL) {
        if (data + 10 < data_max) {
            *data++ = 0; /* Name = root */
            *data++ = 0; *data++ = 41; /* type = OPT */
            *data++ = (uint8_t)(l_max >> 8);
            *data++ = (uint8_t)(l_max & 255); /* Class encodes l_max */
            *data++ = 0; /* Extended rcode =  0, */
            *data++ = 0; /* EDNS version =  0, */
            *data++ = 0; *data++ = 0; /* Flags =  0, */
            *data++ = 0; *data++ = 0; /* zero length RDATA */
        }
        else {
            data = NULL;
        }
    }

    return data;
}

/* Parse the DNS name component of a query or response.
 * Returns the index of the first character after the name.
 */
size_t quicdoq_parse_dns_name(const uint8_t* packet, size_t length, size_t start,
    uint8_t** text_start, uint8_t *text_max)
{
    size_t l = 0;
    size_t name_start = start;
    size_t start_next = 0;
    uint8_t* text = *text_start;

    while (start < length && text != NULL && text < text_max) {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/
            start++;

            if (start_next == 0) {
                start_next = start;
            }
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            if ((start + 2) > length)
            {
                /* error */
                start_next = length;
                break;
            }
            else
            {
                size_t new_start = ((l & 63) << 8) + packet[start + 1];

                if (new_start < name_start)
                {
                    if (start_next == 0) {
                        start_next = start + 2;
                    }
                    start = new_start;
                }
                else {
                    /* Basic restriction to avoid name decoding loops */
                    start_next = length;
                    break;
                }
            }
        }
        else if (l > 0x3F)
        {
            /* found an extension. Don't know how to parse it! */
            start_next = length;
            break;
        }
        else
        {
            /* add a label to the name. */
            if (start + l + 1 > length ||
                text + l + 2 > text_max)
            {
                /* format error */
                *text = 0;
                start_next = length;
                break;
            }
            else
            {
                if (text > *text_start && text + 1 < text_max) {
                    *text++ = '.';
                }

                text = NormalizeNamePart(l, &packet[start + 1], text, text_max);

                start += l + 1;
            }
        }
    }

    if (text != NULL && text + 1 < text_max) {
        *text++ = '.';
    }

    *text_start = text;

    return start_next;
}

size_t quicdoq_skip_dns_name(const uint8_t* packet, size_t length, size_t start)
{
    size_t l = 0;
    size_t start_next = 0;

    while (start < length) {
        l = packet[start];

        if (l == 0)
        {
            /* end of parsing*/
            start++;

            if (start_next == 0) {
                start_next = start;
            }
            break;
        }
        else if ((l & 0xC0) == 0xC0)
        {
            start_next = start + 2;
            if (start_next > length)
            {
                /* error */
                start_next = length;
                break;
            }
        }
        else if (l > 0x3F)
        {
            /* found an extension. Don't know how to parse it! */
            start_next = length;
            break;
        }
        else
        {
            /* add a label to the name. */
            if (start + l + 1 > length)
            {
                /* format error */
                start_next = length;
                break;
            }
            else
            {
                start += l + 1;
            }
        }
    }

    return start_next;
}

/* Convert a DNS RR to a text string.
 */
size_t quicdoq_parse_dns_RR(const uint8_t* packet, size_t length, size_t start,
    uint8_t** text_start, uint8_t * text_max)
{

    int rrtype = 0;
    int rrclass = 0;
    unsigned int ttl = 0;
    int ldata = 0;
    uint8_t* text = *text_start;

    /* Print the DNS name */
    text = quicdoq_add_string(text, text_max, "{ ", 2);
    text = quicdoq_add_label(text, text_max, "NAME", 4);
    text = quicdoq_add_string(text, text_max, ": \"", 3);
    start = quicdoq_parse_dns_name(packet, length, start, &text, text_max);
    text = quicdoq_add_string(text, text_max, "\",\n", 3);

    if ((start + 10) > length)
    {
        text = NULL;
        start = length;
    }
    else
    {
        rrtype = (packet[start] << 8) | packet[start + 1];
        rrclass = (packet[start + 2] << 8) | packet[start + 3];
        ttl = (packet[start + 4] << 24) | (packet[start + 5] << 16)
            | (packet[start + 6] << 8) | packet[start + 7];
        ldata = (packet[start + 8] << 8) | packet[start + 9];
        start += 10;

        if (start + ldata > length){
            text = NULL;
            start = length;
        }
        else {
            /* TODO: specialized data printout for A, AAAA, etc. */
            text = quicdoq_add_label_num(text, text_max, "TYPE", rrtype);
            text = quicdoq_add_string(text, text_max, ", ", 2);
            text = quicdoq_add_label_num(text, text_max, "CLASS", rrclass);
            text = quicdoq_add_string(text, text_max, ", ", 2);
            text = quicdoq_add_label_num(text, text_max, "TTL", ttl);
            text = quicdoq_add_string(text, text_max, ",\n", 2);
            /* TODO: something better than HEX! */
            text = quicdoq_add_label(text, text_max, "RDATAHEX", 8);
            text = quicdoq_add_string(text, text_max, ": \"", 3);
            text = quicdoq_add_hex(text, text_max, packet + start, ldata);
            text = quicdoq_add_string(text, text_max, "\"}", 2);
            start += ldata;
        }
    }

    *text_start = text;

    return start;
}


/* Convert a DNS Query  to a text string.
 * Example of query:
 * { "ID": 32784, "QR": 0, "Opcode": 0, "AA": 0,
 *  "TC": 0, "RD": 0, "RA": 0, "AD": 0, "CD": 0,
 *  "RCODE": 0, "QDCOUNT": 1, "ANCOUNT": 0,
 *  "NSCOUNT": 0, "ARCOUNT": 0,
 *  "QNAME": "example.com.",
 *  "QTYPE": 1, "QCLASS": 1}
 * Example of response:
 * { "ID": 32784, "QR": 1, "AA": 1, "RCODE": 0,
 *   "QDCOUNT": 1, "ANCOUNT": 1, "NSCOUNT": 1,
 *   "ARCOUNT": 0,
 *   "QNAME": "example.com.",
 *   "QTYPE": 1, "QCLASS": 1,
 *   "answerRRs": [ { "NAME": "example.com.",
 *      "TYPE": 1, "CLASS": 1,
 *      "TTL": 3600,
 *      "RDATAHEX": "C0000201" },
 *       { "NAME": "example.com.",
 *       "TYPE": 1, "CLASS": 1,
 *       "TTL": 3600,
 *       "RDATAHEX": "C000AA01" } ],
 *   "authorityRRs": [ { "NAME": "ns.example.com.",
 *       "TYPE": 1, "CLASS": 1,
 *       "TTL": 28800,
 *       "RDATAHEX": "CB007181" } ]
 * }
 *
 * The RFC also has a format specification for a joint-query-response record,
 * which might be useful at some point. We will see that later, but it
 * might be more appropriate to support one of the CBOR based logging formats.
 */
size_t quicdoq_parse_dns_query(const uint8_t* packet, size_t length, size_t start,
    uint8_t** text_start, uint8_t* text_max)
{
    if (*text_start == NULL || start + 12 > length) {
        *text_start = NULL;
        start = length;
    }
    else
    {
        uint8_t* text = *text_start;
        const uint8_t* q_start = &packet[start];
        uint16_t id = (((uint16_t)q_start[0]) << 8) | packet[1];
        unsigned int QR = (q_start[2] >> 7) & 1;
        unsigned int opcode = (q_start[2] >> 3) & 15;
        unsigned int AA = (q_start[2] >> 2) & 1;
        unsigned int TC = (q_start[2] >> 1) & 1;
        unsigned int RD = q_start[2] & 1;
        unsigned int RA = (q_start[3] >> 7) & 1;
        unsigned int AD = (q_start[3] >> 5) & 1;
        unsigned int CD = (q_start[3] >> 4) & 1;
        unsigned int rcode = q_start[3] & 15;
        uint16_t qdcount = (q_start[4] << 8) | q_start[5];
        uint16_t ancount = (q_start[6] << 8) | q_start[7];
        uint16_t nscount = (q_start[8] << 8) | q_start[9];
        uint16_t arcount = (q_start[10] << 8) | q_start[11];
        uint16_t qtype = 0;
        uint16_t qclass = 0;
        uint16_t xrcount[3];
        char const* xrname[3] = { "answerRRs", "authorityRRs", "additionalRRs" };

        *text = 0;

        xrcount[0] = ancount;
        xrcount[1] = nscount;
        xrcount[2] = arcount;

        text = quicdoq_add_string(text, text_max, "{ ", 2);
        text = quicdoq_add_label_num(text, text_max, "ID", id);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "QR", QR);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "Opcode", opcode);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "AA", AA);
        text = quicdoq_add_string(text, text_max, ",\n", 2);
        text = quicdoq_add_label_num(text, text_max, "TC", TC);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "RD", RD);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "RA", RA);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "AD", AD);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "CD", CD);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "RCODE", rcode);
        text = quicdoq_add_string(text, text_max, ",\n", 2);
        text = quicdoq_add_label_num(text, text_max, "QDCOUNT", qdcount);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "ANCOUNT", ancount);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "NSCOUNT", nscount);
        text = quicdoq_add_string(text, text_max, ", ", 2);
        text = quicdoq_add_label_num(text, text_max, "ARCOUNT", arcount);

        start += 12;

        for (uint16_t nq = 0; start < length && text != NULL && nq < qdcount; nq++) {
            text = quicdoq_add_string(text, text_max, ",\n", 2);
            text = quicdoq_add_label(text, text_max, "QNAME", 5);
            text = quicdoq_add_string(text, text_max, ": \"", 3);
            start = quicdoq_parse_dns_name(packet, length, start, &text, text_max);
            text = quicdoq_add_string(text, text_max, "\", ", 3);

            if (start + 4 <= length && text != NULL) {
                qtype = (((uint16_t)packet[start]) << 8) | packet[start + 1];
                qclass = (((uint16_t)packet[start + 2]) << 8) | packet[start + 3];
                start += 4;

                text = quicdoq_add_label_num(text, text_max, "QTYPE", qtype);
                text = quicdoq_add_string(text, text_max, ", ", 2);
                text = quicdoq_add_label_num(text, text_max, "QCLASS", qclass);
            }
            else {
                start = length;
                text = NULL;
            }
        }

        for (int xr = 0; xr < 3; xr++) {
            if (xrcount[xr] > 0) {
                text = quicdoq_add_string(text, text_max, ",\n", 2);
                text = quicdoq_add_label(text, text_max, xrname[xr], strlen(xrname[xr]));
                text = quicdoq_add_string(text, text_max, ": [", 3);
                for (uint32_t i = 0; start < length && text != NULL && i < xrcount[xr]; i++)
                {
                    if (i == 0) {
                        text = quicdoq_add_char(text, text_max, '\n');
                    }
                    else {
                        /* Add comma & newline after previous RR */
                        text = quicdoq_add_string(text, text_max, ",\n", 2);
                    }
                    start = quicdoq_parse_dns_RR(packet, length, start, &text, text_max);
                }
                text = quicdoq_add_char(text, text_max, ']');
            }
        }
        text = quicdoq_add_string(text, text_max, "}", 1);
        *text_start = text;
    }

    return start;
}

/* Get RR Code from RR Name
 */

const quicdoq_rr_entry_t rr_table[] = {
    { "A", 1},
    { "NS", 2},
    { "MD", 3},
    { "MF", 4},
    { "CNAME", 5},
    { "SOA", 6},
    { "MB", 7},
    { "MG", 8},
    { "MR", 9},
    { "NULL", 10},
    { "WKS", 11},
    { "PTR", 12},
    { "HINFO", 13},
    { "MINFO", 14},
    { "MX", 15},
    { "TXT", 16},
    { "RP", 17},
    { "AFSDB", 18},
    { "X25", 19},
    { "ISDN", 20},
    { "RT", 21},
    { "NSAP", 22},
    { "NSAP-PTR", 23},
    { "SIG", 24},
    { "KEY", 25},
    { "PX", 26},
    { "GPOS", 27},
    { "AAAA", 28},
    { "LOC", 29},
    { "NXT", 30},
    { "EID", 31},
    { "NIMLOC", 32},
    { "SRV", 33},
    { "ATMA", 34},
    { "NAPTR", 35},
    { "KX", 36},
    { "CERT", 37},
    { "A6", 38},
    { "DNAME", 39},
    { "SINK", 40},
    { "OPT", 41},
    { "APL", 42},
    { "DS", 43},
    { "SSHFP", 44},
    { "IPSECKEY", 45},
    { "RRSIG", 46},
    { "NSEC", 47},
    { "DNSKEY", 48},
    { "DHCID", 49},
    { "NSEC3", 50},
    { "NSEC3PARAM", 51},
    { "TLSA", 52},
    { "SMIMEA", 53},
    { "Unassigned", 54},
    { "HIP", 55},
    { "NINFO", 56},
    { "RKEY", 57},
    { "TALINK", 58},
    { "CDS", 59},
    { "CDNSKEY", 60},
    { "OPENPGPKEY", 61},
    { "CSYNC", 62},
    { "ZONEMD", 63},
    { "SPF", 99},
    { "UINFO", 100},
    { "UID", 101},
    { "GID", 102},
    { "UNSPEC", 103},
    { "NID", 104},
    { "L32", 105},
    { "L64", 106},
    { "LP", 107},
    { "EUI48", 108},
    { "EUI64", 109},
    { "TKEY", 249},
    { "TSIG", 250},
    { "IXFR", 251},
    { "AXFR", 252},
    { "MAILB", 253},
    { "MAILA", 254},
    { "*", 255},
    { "URI", 256},
    { "CAA", 257},
    { "AVC", 258},
    { "DOA", 259},
    { "AMTRELAY", 260},
    { "TA", 32768},
    { "DLV", 32769} };

const size_t nb_rr_table = sizeof(rr_table) / sizeof(quicdoq_rr_entry_t);

uint16_t quicdoq_get_rr_type(char const* rr_name) {
    size_t x;
    uint16_t rr_type = 0;

    for (x = 0; x < nb_rr_table; x++) {
        if (strcmp(rr_name, rr_table[x].rr_name) == 0) {
            rr_type = rr_table[x].rr_type;
            break;
        }
    }

    if (rr_type == 0) {
        for (int i = 0; 1; i++) {
            int c = rr_name[i];

            if (c == 0) {
                break;
            } else if (c >= '0' && c <= '9') {
                rr_type = 10 * rr_type + (uint16_t)(c - '0');
            }
            else {
                rr_type = UINT16_MAX;
                break;
            }
        }
    }

    return rr_type;
}
