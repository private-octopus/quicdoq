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

/* UDP Relay:
 * Forward queries received over Quic to a backend server at specified
 * address and port. Retrieve the corresponding response. Repeat
 * queries on timer if responses to not come back.
 *
 * The UDP relay is designed to fit in the "virtual time" test architecture.
 * It has two entry points:
 * - The callback function for submission and cancelling of requests,
 * - The prepare function to test whether there is a need to send a UDP packet,
 * - The incoming function when packets arrive from the UDP server.
 * The UDP relay maintains a "next wake time", the next time at which a
 * message might be ready to be sent. This includes transmission of
 * original requests, typically immediate, and retransmission on timer.
 */

quicdog_udp_queued_t* quicdoq_udp_find_by_id(quicdoq_udp_ctx_t* udp_ctx, uint16_t id)
{
    quicdog_udp_queued_t* next = udp_ctx->first_query;

    while (next != NULL && next->udp_query_id != id) {
        next = next->next;
    }

    return next;
}

void quicdoq_udp_insert_in_list(quicdoq_udp_ctx_t* udp_ctx, quicdog_udp_queued_t* quq_ctx)
{
    quicdog_udp_queued_t* previous = NULL;
    quicdog_udp_queued_t* next = udp_ctx->first_query;

    while (next != NULL && next->next_send_time <= quq_ctx->next_send_time) {
        previous = next;
        next = next->next;
    }

    quq_ctx->previous = previous;
    if (previous == NULL) {
        udp_ctx->first_query = quq_ctx;
    }
    else {
        previous->next = quq_ctx;
    }

    quq_ctx->next = next;
    if (next == NULL) {
        udp_ctx->last_query = quq_ctx;
    }
    else {
        next->previous = quq_ctx;
    }

    udp_ctx->next_wake_time = udp_ctx->first_query->next_send_time;
}

void quicdoq_udp_remove_from_list(quicdoq_udp_ctx_t* udp_ctx, quicdog_udp_queued_t* quq_ctx)
{
    if (quq_ctx->previous == NULL) {
        udp_ctx->first_query = quq_ctx->next;
    }
    else {
        quq_ctx->previous->next = quq_ctx->next;
    }

    if (quq_ctx->next == NULL) {
        udp_ctx->last_query = quq_ctx->previous;
    }
    else {
        quq_ctx->next->previous = quq_ctx->previous;
    }
}

void quicdoq_udp_reinsert_in_list(quicdoq_udp_ctx_t* udp_ctx, quicdog_udp_queued_t* quq_ctx)
{
    quicdoq_udp_remove_from_list(udp_ctx, quq_ctx);
    quicdoq_udp_insert_in_list(udp_ctx, quq_ctx);
}

int quicdoq_udp_cancel_query(quicdoq_udp_ctx_t* udp_ctx, quicdog_udp_queued_t* quq_ctx, uint64_t error_code)
{
    int ret = quicdoq_cancel_response(udp_ctx->quicdoq_ctx, quq_ctx->query_ctx, QUICDOQ_ERROR_RESPONSE_TOO_LONG);
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(error_code);
#endif
    /* Remove the context from the list and delete it */
    quicdoq_udp_remove_from_list(udp_ctx, quq_ctx);
    free(quq_ctx);

    if (udp_ctx->first_query == NULL) {
        udp_ctx->next_wake_time = UINT64_MAX;
    }
    else {
        udp_ctx->next_wake_time = udp_ctx->first_query->next_send_time;
    }

    return ret;
}

int quicdoq_udp_callback(
    quicdoq_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdoq_udp_ctx_t* udp_ctx = (quicdoq_udp_ctx_t*)callback_ctx;
    quicdog_udp_queued_t* quq_ctx = NULL;

    switch (callback_code) {
    case quicdoq_incoming_query: /* Incoming callback query */
        /* Pick the next available query ID */
        for (int i = 0; i < 4; i++) {
            quq_ctx = quicdoq_udp_find_by_id(udp_ctx, udp_ctx->next_id);
            if (quq_ctx == NULL) {
                break;
            }
            else {
                udp_ctx->next_id++;
            }
        }

        if (quq_ctx != NULL) {
            /* Failure. No more avaliable query ID. */
            ret = -1;
        }
        else {
            /* Allocate a query context */
            quq_ctx = (quicdog_udp_queued_t*)malloc(sizeof(quicdog_udp_queued_t));

            if (quq_ctx == NULL) {
                /* Failure. Not enough memory. */
                ret = -1;
            }
            else {
                /* Add the query to the pending queue.
                 * update the sending time. */
                memset(quq_ctx, 0, sizeof(quicdog_udp_queued_t));
                quq_ctx->query_ctx = query_ctx;
                quq_ctx->query_arrival_time = current_time;
                quq_ctx->next_send_time = current_time;
                quq_ctx->udp_query_id = udp_ctx->next_id++;

                quicdoq_udp_insert_in_list(udp_ctx, quq_ctx);
            }
        }

        break;
    case quicdoq_query_cancelled: /* Query cancelled before response provided */
    case quicdoq_query_failed: /* Query failed for reasons other than cancelled. */
        /* remove response from queue, mark it cancelled */
        break;
    default: /* callback code not expected on server */
        ret = -1;
        break;
    }

    return ret;

}

void quicdoq_udp_prepare_next_packet(quicdoq_udp_ctx_t* udp_ctx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, int* to_len, struct sockaddr_storage* p_addr_from, int* from_len, int* if_index)
{
    quicdog_udp_queued_t* quq_ctx = udp_ctx->first_query;

    *send_length = 0;

    /* Double list is ordered by next send time */
    if (quq_ctx == NULL) {
        udp_ctx->next_wake_time = UINT64_MAX;
    }
    else if (quq_ctx->next_send_time > current_time) {
        /* Do nothing */
    } else {
        if (quq_ctx->nb_sent > QUICDOQ_UDP_MAX_REPEAT) {
            /* Query failed. Delete, report failure */
            picoquic_log_app_message(quq_ctx->query_ctx->quic, &quq_ctx->query_ctx->cid, "Quicdoq: Cancel after max repeat, udp query #%d.\n", quq_ctx->udp_query_id);
            (void)quicdoq_udp_cancel_query(udp_ctx, quq_ctx, QUICDOQ_ERROR_RESPONSE_TIME_OUT);
        }
        else if (quq_ctx->query_ctx->query_length > send_buffer_max) {
            /* Cannot be sent. Delete, send back a query too long failure */
            picoquic_log_app_message(quq_ctx->query_ctx->quic, &quq_ctx->query_ctx->cid, "Quicdoq: Response too long, udp query #%d.\n", quq_ctx->udp_query_id);
            (void)quicdoq_udp_cancel_query(udp_ctx, quq_ctx, QUICDOQ_ERROR_QUERY_TOO_LONG);
        }
        else {
            send_buffer[0] = (uint8_t)(quq_ctx->udp_query_id >> 8);
            send_buffer[1] = (uint8_t)(quq_ctx->udp_query_id & 0xFF);
            memcpy(send_buffer + 2, quq_ctx->query_ctx->query + 2, quq_ctx->query_ctx->query_length - 2);
            *send_length = quq_ctx->query_ctx->query_length;

            quq_ctx->nb_sent++;
            picoquic_log_app_message(quq_ctx->query_ctx->quic, &quq_ctx->query_ctx->cid, "Quicdoq: preparing UDP query #%d after %"PRIu64 "us.\n", 
                quq_ctx->udp_query_id, current_time - quq_ctx->query_arrival_time);
            quq_ctx->next_send_time = current_time + udp_ctx->rto;
            quicdoq_udp_reinsert_in_list(udp_ctx, quq_ctx);
            *to_len = picoquic_store_addr(p_addr_to, (struct sockaddr*)&udp_ctx->udp_addr);
            *from_len = picoquic_store_addr(p_addr_from, (struct sockaddr*) & udp_ctx->local_addr);
            if (udp_ctx->if_index >= 0) {
                *if_index = udp_ctx->if_index;
            }
        }
    }
}

void quicdoq_udp_incoming_packet(
    quicdoq_udp_ctx_t* udp_ctx,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_to,
    int if_index_to,
    uint64_t current_time)
{
    if (length < 2) {
        /* Bad packet */
    }
    else {
        uint16_t packet_id = (bytes[0] << 8) | bytes[1];
        quicdog_udp_queued_t* quq_ctx = quicdoq_udp_find_by_id(udp_ctx, packet_id);

        if (quq_ctx == NULL) {
            /* Duplicate or random packet */
        }
        else if (length > quq_ctx->query_ctx->response_max_size) {
            /* Reponse is too long */
            picoquic_log_app_message(quq_ctx->query_ctx->quic, &quq_ctx->query_ctx->cid, "Quicdoq: incoming UDP response too long, query  #%d.\n", quq_ctx->udp_query_id);
            (void)quicdoq_udp_cancel_query(udp_ctx, quq_ctx, QUICDOQ_ERROR_RESPONSE_TOO_LONG);
        }
        else
        {
            /* Update the local address */
            picoquic_store_addr(&udp_ctx->local_addr, addr_to);
            udp_ctx->if_index = if_index_to;

            /* Store the response */
            quq_ctx->query_ctx->response[0] = quq_ctx->query_ctx->query[0];
            quq_ctx->query_ctx->response[1] = quq_ctx->query_ctx->query[1];
            memcpy(quq_ctx->query_ctx->response + 2, bytes + 2, length - 2);
            quq_ctx->query_ctx->response_length = length;
            /* Post to the quicdoq server */
            picoquic_log_app_message(quq_ctx->query_ctx->quic, &quq_ctx->query_ctx->cid, "Quicdoq: incoming UDP to query #%d after %"PRIu64 "us. Posted to Quicdoq server.\n", 
                quq_ctx->udp_query_id, current_time - quq_ctx->query_arrival_time);
            (void)quicdoq_post_response(quq_ctx->query_ctx);
            /* Remove the context from the list and delete it */
            quicdoq_udp_remove_from_list(udp_ctx, quq_ctx);
            free(quq_ctx);
        }
    }

    if (udp_ctx->first_query == NULL) {
        udp_ctx->next_wake_time = UINT64_MAX;
    }
    else {
        udp_ctx->next_wake_time = udp_ctx->first_query->next_send_time;
    }
}

uint64_t quicdoq_next_udp_time(quicdoq_udp_ctx_t* udp_ctx)
{
    return udp_ctx->next_wake_time;
}

quicdoq_udp_ctx_t* quicdoq_create_udp_ctx(quicdoq_ctx_t* quicdoq_ctx, struct sockaddr* addr)
{
    quicdoq_udp_ctx_t* udp_ctx = (quicdoq_udp_ctx_t*)malloc(sizeof(quicdoq_udp_ctx_t));
    if (udp_ctx != NULL) {
        memset(udp_ctx, 0, sizeof(quicdoq_udp_ctx_t));
        picoquic_store_addr(&udp_ctx->udp_addr, addr);
        udp_ctx->quicdoq_ctx = quicdoq_ctx;
        udp_ctx->next_wake_time = UINT64_MAX;
        udp_ctx->rto = QUICDOQ_UDP_DEFAULT_RTO;
        udp_ctx->if_index = -1;
    }
    return udp_ctx;
}

void quicdoq_delete_udp_ctx(quicdoq_udp_ctx_t* udp_ctx)
{
    quicdog_udp_queued_t* quq_ctx;

    while ((quq_ctx = udp_ctx->first_query) != NULL) {
        /* Reponse is too long */
        (void)quicdoq_udp_cancel_query(udp_ctx, quq_ctx, QUICDOQ_ERROR_INTERNAL);
    }

    free(quq_ctx);
}