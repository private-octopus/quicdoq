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
    picoquic_cnx_t* cnx;
    int is_server;
    struct st_quicdoq_ctx_t* quicdog_ctx;
    quicdoq_stream_ctx_t* first_stream;
    quicdoq_stream_ctx_t* last_stream;
} quicdoq_cnx_ctx_t;

/* Quicdoq context */
typedef struct st_quicdoq_ctx_t {
    picoquic_quic_t* quic; /* The quic context for the DoQ service */
    /* Todo: message passing and synchronization */
    /* Todo: sockets, etc */
    quicdoq_app_cb_fn app_cb_fn; /* Applcation callback function */
    void* app_cb_ctx; /* callback_ctx provided to applications */
    quicdoq_cnx_ctx_t default_callback_ctx; /* Default context provided to new connections */
} quicdoq_ctx_t;

/* DoQ stream handling */
typedef struct st_quicdoq_stream_ctx_t {
    uint64_t stream_id;
    quicdoq_stream_ctx_t* next_stream;
    quicdoq_stream_ctx_t* previous_stream;
    quicdoq_query_ctx_t* query_ctx;

    unsigned int client_mode : 1;
} quicdoq_stream_ctx_t;

quicdoq_stream_ctx_t* quicdoq_find_or_create_stream(
    uint64_t stream_id,
    quicdoq_cnx_ctx_t* ctx,
    int should_create);

void quicdoq_delete_stream_ctx(quicdoq_cnx_ctx_t* ctx, quicdoq_stream_ctx_t* stream_ctx);

int quicdoq_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

int quicdoq_callback_data(picoquic_cnx_t* cnx, quicdoq_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event, quicdoq_cnx_ctx_t* callback_ctx);

int quicdoq_callback_prepare_to_send(picoquic_cnx_t* cnx, uint64_t stream_id, quicdoq_stream_ctx_t* stream_ctx,
    void* bytes, size_t length, quicdoq_cnx_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* quicdoq_client_internal__H */