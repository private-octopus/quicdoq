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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include "quicdoq.h"
#include "quicdoq_internal.h"

/* Per stream context, DoQ client. This context has to be created
 * on servers for incoming streams upon reception of first byte,
 * and on clients before handling the client query.
 */

quicdoq_stream_ctx_t* quicdoq_find_or_create_stream(uint64_t stream_id, quicdoq_cnx_ctx_t* ctx, int should_create)
{
    quicdoq_stream_ctx_t* stream_ctx = NULL;

    /* if stream is already present, check its state. New bytes? */
    stream_ctx = ctx->first_stream;
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (quicdoq_stream_ctx_t*)
            malloc(sizeof(quicdoq_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            DBG_PRINTF("Could not allocate data for stream %llu\n", (unsigned long long)stream_id);
        } else {
            memset(stream_ctx, 0, sizeof(quicdoq_stream_ctx_t));
            if (ctx->last_stream == NULL) {
                ctx->first_stream = stream_ctx;
            }
            else {
                ctx->last_stream->next_stream = stream_ctx;
            }
            ctx->last_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
            /* If this is a server stream, allocate a query structure */
        }
    }

    return stream_ctx;
}

void quicdoq_delete_stream_ctx(quicdoq_cnx_ctx_t* ctx, quicdoq_stream_ctx_t* stream_ctx)
{
    if (ctx != NULL && stream_ctx != NULL) {
        /* If this is a server stream, delete the query */

        /* Remove the links */
        if (stream_ctx->previous_stream == NULL) {
            ctx->first_stream = stream_ctx->next_stream;
        }
        else {
            stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
        }
        if (stream_ctx->next_stream == NULL) {
            ctx->last_stream = stream_ctx->previous_stream;
        }
        else {
            stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
        }
        free(stream_ctx);
    }
}

/* On the data callback, fill the bytes in the relevant query field, and if needed signal the app. */

int quicdoq_callback_data(picoquic_cnx_t* cnx, quicdoq_stream_ctx_t* stream_ctx, uint64_t stream_id,
    uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, quicdoq_cnx_ctx_t* callback_ctx)
{
    int ret = 0;

    return ret;
}

/* On the prepare to send callback, provide data */
int quicdoq_callback_prepare_to_send(picoquic_cnx_t* cnx, uint64_t stream_id, quicdoq_stream_ctx_t* stream_ctx,
    void* bytes, size_t length, quicdoq_cnx_ctx_t* ctx)
{
    return -1;
}

/* Create a per connection context when a connection is either requested or incoming */

/*
 * DOQ client call back.
 *
 * Create a context for each client connection.
 * The context holds a list of per stream context, used for managing incoming 
 * and outgoing queries, and a pointer to the DoQ context.
 */

quicdoq_cnx_ctx_t* quicdoq_callback_create_context(quicdoq_cnx_ctx_t* old_ctx)
{
    quicdoq_cnx_ctx_t* ctx = (quicdoq_cnx_ctx_t*)
        malloc(sizeof(quicdoq_cnx_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(quicdoq_cnx_ctx_t));
        ctx->first_stream = NULL;
        ctx->last_stream = NULL;
        ctx->quicdog_ctx = old_ctx->quicdog_ctx;
    }
    return ctx;
}

void quicdoq_callback_delete_context(quicdoq_cnx_ctx_t* ctx)
{
    if (ctx != NULL) {
        while (ctx->first_stream != NULL) {
            quicdoq_delete_stream_ctx(ctx, ctx->first_stream);
        }
        free(ctx);
    }
}


int quicdoq_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    quicdoq_cnx_ctx_t* ctx = (quicdoq_cnx_ctx_t*)callback_ctx;
    quicdoq_stream_ctx_t* stream_ctx = (quicdoq_stream_ctx_t*)v_stream_ctx;

    /* TODO: pass quicdog context in callback in compatible way */

    if (callback_ctx == NULL) {
        /* Unexpected error */
        picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        return -1;
    } else if (ctx->cnx == NULL){
        ctx = quicdoq_callback_create_context(ctx);
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, quicdoq_callback, ctx);
        }
    }
    else {
        ctx = (quicdoq_cnx_ctx_t*)callback_ctx;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = quicdoq_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            quicdoq_callback_delete_context(ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            /* Should trigger a failure */
            break;
        case picoquic_callback_prepare_to_send:
            ret = quicdoq_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx);
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what DoQ expects */
        case picoquic_callback_datagram:/* No datagram support in DoQ */
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_request_alpn_list: /* Provide the list of supported ALPN */
        case picoquic_callback_set_alpn: /* Set ALPN to negotiated value */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

quicdoq_query_ctx_t* quicdoq_create_query_ctx(size_t query_length, size_t response_max_size)
{
    return NULL;
}   

void  quicdoq_delete_query_ctx(quicdoq_query_ctx_t* query_ctx)
{

}

int quicdoq_create(void** quicdoq_ctx, quicdoq_app_cb_fn* server_cb, void* server_callback_ctx)
{
    return 0;
}

void quicdoq_delete(void* quicdoq_ctx)
{
}

int quicdoq_post_query(void* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    return 0;
}

int quicdoq_cancel_query(void* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    return 0;
}

int quicdoq_post_response(void* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    return 0;
}

int quicdoq_cancel_response(void* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    return 0;
}
