/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#ifndef quicdoq_client_internal_H
#define quicdoq_client_internal_H

#include "picoquic.h"
#include "quicdoq.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Implementation of the quicdoq application on top of picoquic. 
 * 
 * The quicdoq context is created by the call to quicdoq_create, which
 * starts the operation. It is deleted by a call to  */

/* Forward reference */
typedef struct st_quicdoq_stream_ctx_t quicdoq_stream_ctx_t;

/* Quicdoc per connection context
 * This is the argument passed by the callback context.
 * The Quic context provides by default an instance of this context in
 * which the connection context cnx is NULL. Upon finding that, the
 * code creates an actual per connection context in the first callback
 * for that connection.
 */
typedef struct st_quicdoq_cnx_ctx_t {
    struct st_quicdoq_cnx_ctx_t* next_cnx;
    struct st_quicdoq_cnx_ctx_t* previous_cnx;
    struct st_quicdoq_ctx_t* quicdoq_ctx;

    char* sni;
    struct sockaddr_storage addr;
    picoquic_cnx_t* cnx;
    int is_server;

    uint64_t next_available_stream_id; /* starts with stream 0 on client */
    quicdoq_stream_ctx_t* first_stream;
    quicdoq_stream_ctx_t* last_stream;

} quicdoq_cnx_ctx_t;

/* Quicdoq context */
typedef struct st_quicdoq_ctx_t {
    picoquic_quic_t* quic; /* The quic context for the DoQ service */
    /* Todo: message passing and synchronization */
    /* Todo: sockets, etc */
    quicdoq_app_cb_fn app_cb_fn; /* Application callback function */
    void* app_cb_ctx; /* callback_ctx provided to applications */
    quicdoq_cnx_ctx_t default_callback_ctx; /* Default context provided to new connections */
    struct st_quicdoq_cnx_ctx_t* first_cnx; /* First in double linked list of open connections in this context */
    struct st_quicdoq_cnx_ctx_t* last_cnx; /* last in list of open connections in this context */
} quicdoq_ctx_t;

/* DoQ stream handling */
typedef struct st_quicdoq_stream_ctx_t {
    uint64_t stream_id;
    quicdoq_stream_ctx_t* next_stream;
    quicdoq_stream_ctx_t* previous_stream;
    quicdoq_cnx_ctx_t* cnx_ctx;
    quicdoq_query_ctx_t* query_ctx;
    size_t bytes_sent;

    unsigned int client_mode : 1;
} quicdoq_stream_ctx_t;

quicdoq_stream_ctx_t* quicdoq_find_or_create_stream(
    uint64_t stream_id,
    quicdoq_cnx_ctx_t* cnx_ctx,
    int should_create);

void quicdoq_delete_stream_ctx(quicdoq_cnx_ctx_t* cnx_ctx, quicdoq_stream_ctx_t* stream_ctx);

int quicdoq_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

int quicdoq_callback_data(picoquic_cnx_t* cnx, quicdoq_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event, quicdoq_cnx_ctx_t* cnx_ctx);

int quicdoq_callback_prepare_to_send(picoquic_cnx_t* cnx, uint64_t stream_id, quicdoq_stream_ctx_t* stream_ctx,
    void* bytes, size_t length, quicdoq_cnx_ctx_t* cnx_ctx);

/* Set the parameters to the preferred DoQ values. */
int quicdoq_set_tp(quicdoq_ctx_t* quicdoq_ctx, picoquic_cnx_t* cnx, uint64_t max_size);

/* Handling of UDP relay */

#define QUICDOQ_UDP_MAX_REPEAT 4
#define QUICDOQ_UDP_DEFAULT_RTO 1000000

typedef struct st_quicdog_udp_queued_t {
    struct st_quicdog_udp_queued_t* next;
    struct st_quicdog_udp_queued_t* previous;

    quicdoq_query_ctx_t* query_ctx;
    uint64_t query_arrival_time;
    uint64_t next_send_time;
    int nb_sent;
    uint16_t udp_query_id;
} quicdog_udp_queued_t;

typedef struct st_quicdoq_udp_ctx_t {
    quicdoq_ctx_t* quicdoq_ctx;
    uint64_t next_wake_time;
    struct sockaddr_storage udp_addr;
    struct sockaddr_storage local_addr;
    int if_index;

    quicdog_udp_queued_t* first_query;
    quicdog_udp_queued_t* last_query;

    uint64_t srtt;
    uint64_t drtt;
    uint64_t rtt_min;
    uint64_t rto;

    uint16_t next_id;
} quicdoq_udp_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* quicdoq_client_internal__H */