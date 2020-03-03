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

/* Per stream context, DoQ client. This context has to be created
 * on servers for incoming streams upon reception of first byte,
 * and on clients before handling the client query.
 */

quicdoq_stream_ctx_t* quicdoq_find_or_create_stream(uint64_t stream_id, quicdoq_cnx_ctx_t* cnx_ctx, int should_create)
{
    quicdoq_stream_ctx_t* stream_ctx = NULL;

    /* if stream is already present, check its state. New bytes? */
    stream_ctx = cnx_ctx->first_stream;
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
            if (cnx_ctx->last_stream == NULL) {
                cnx_ctx->first_stream = stream_ctx;
            }
            else {
                cnx_ctx->last_stream->next_stream = stream_ctx;
            }
            cnx_ctx->last_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
            stream_ctx->cnx_ctx = cnx_ctx;
        }
    }

    return stream_ctx;
}

void quicdoq_delete_stream_ctx(quicdoq_cnx_ctx_t* cnx_ctx, quicdoq_stream_ctx_t* stream_ctx)
{
    if (cnx_ctx != NULL && stream_ctx != NULL) {
        /* If this is a server stream, delete the query */

        /* Remove the links */
        if (stream_ctx->previous_stream == NULL) {
            cnx_ctx->first_stream = stream_ctx->next_stream;
        }
        else {
            stream_ctx->previous_stream->next_stream = stream_ctx->next_stream;
        }
        if (stream_ctx->next_stream == NULL) {
            cnx_ctx->last_stream = stream_ctx->previous_stream;
        }
        else {
            stream_ctx->next_stream->previous_stream = stream_ctx->previous_stream;
        }
        free(stream_ctx);
    }
}

/* On the data callback, fill the bytes in the relevant query field, and if needed signal the app. */

int quicdoq_callback_data(picoquic_cnx_t* cnx, quicdoq_stream_ctx_t* stream_ctx, uint64_t stream_id,
    uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, quicdoq_cnx_ctx_t* cnx_ctx)
{
    int ret = 0;

    if (cnx_ctx->is_server) {
        if (stream_ctx == NULL) {
            /* Incoming data, server size, requires a context creation */
            stream_ctx = quicdoq_find_or_create_stream(stream_id, cnx_ctx, 1);
            if (stream_ctx == NULL) {
                picoquic_connection_id_t cid = picoquic_get_logging_cnxid(cnx);
                DBG_PRINTF("Cannot create server context for server stream  #%llu", (unsigned long long)stream_id);
                picoquic_log_app_message(picoquic_get_quic_ctx(cnx), &cid, "Quicdoq: Cannot create server context for server stream  #%llu.\n", (unsigned long long)stream_id);
                ret = -1;
            }
            else {
                /* If this is a server stream, allocate a query structure */
                stream_ctx->query_ctx = quicdoq_create_query_ctx(1024, 4096);
                if (stream_ctx->query_ctx == NULL) {
                    picoquic_connection_id_t cid = picoquic_get_logging_cnxid(cnx);
                    DBG_PRINTF("Cannot create query context for server stream  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(picoquic_get_quic_ctx(cnx), &cid, "Quicdoq: Cannot create query context for server stream  #%llu\n", (unsigned long long)stream_id);
                    quicdoq_delete_stream_ctx(cnx_ctx, stream_ctx);
                    ret = -1;
                }
                else {
                    /* On the server side, there is no call back per se, but we
                     * ned to associate responses with the stream context 
                     * TODO: check what happens if the server connection disappears. */
                    stream_ctx->query_ctx->client_cb_ctx = stream_ctx;
                    stream_ctx->query_ctx->quic = picoquic_get_quic_ctx(cnx);
                    stream_ctx->query_ctx->cid = picoquic_get_logging_cnxid(cnx);
                }
            }
        }

        if (ret == 0) {
            if (stream_ctx->query_ctx->query_length + length > stream_ctx->query_ctx->query_max_size){
                DBG_PRINTF("Incoming query too long for server stream  #%llu", (unsigned long long)stream_id);
                picoquic_log_app_message(stream_ctx->query_ctx->quic, &stream_ctx->query_ctx->cid, "Quicdoq: Incoming query too long for server stream  #%llu.\n", (unsigned long long)stream_id);
                ret = -1;
            }
            else {
                /* Copy incoming data into query context */
                memcpy(stream_ctx->query_ctx->query + stream_ctx->query_ctx->query_length,
                    bytes, length);
                stream_ctx->query_ctx->query_length += (uint16_t)length;

                if (fin_or_event == picoquic_callback_stream_fin) {
                    /* Query has arrived, apply the call back */
                    ret = cnx_ctx->quicdoq_ctx->app_cb_fn(quicdoq_incoming_query,
                        cnx_ctx->quicdoq_ctx->app_cb_ctx, stream_ctx->query_ctx,
                        picoquic_get_quic_time(cnx_ctx->quicdoq_ctx->quic));
                }
            }
        }
    }
    else {
        if (stream_ctx == NULL) {
            picoquic_connection_id_t cid = picoquic_get_logging_cnxid(cnx);
            DBG_PRINTF("Data arrived on client stream  #%llu before context creation", (unsigned long long)stream_id);
            picoquic_log_app_message(picoquic_get_quic_ctx(cnx), &cid, "Quicdoq: Data arrived on client stream  #%llu before context creation.\n", (unsigned long long)stream_id);
            ret = -1;
        }
        else {
            if (stream_ctx->query_ctx->response_length + length > stream_ctx->query_ctx->response_max_size) {
                DBG_PRINTF("Incoming response too long for client stream  #%llu", (unsigned long long)stream_id);
                picoquic_log_app_message(stream_ctx->query_ctx->quic, &stream_ctx->query_ctx->cid, "Quicdoq: Incoming response too long for client stream  #%llu.\n", (unsigned long long)stream_id);
                ret = -1;
            }
            else {
                /* Copy incoming data into query context */
                memcpy(stream_ctx->query_ctx->response + stream_ctx->query_ctx->response_length,
                    bytes, length);
                stream_ctx->query_ctx->response_length += (uint16_t)length;

                if (fin_or_event == picoquic_callback_stream_fin) {
                    /* Query has arrived, apply the call back */
                    ret = cnx_ctx->quicdoq_ctx->app_cb_fn(quicdoq_response_complete,
                        cnx_ctx->quicdoq_ctx->app_cb_ctx, stream_ctx->query_ctx,
                        picoquic_get_quic_time(cnx_ctx->quicdoq_ctx->quic));
                    /* Close the stream on the client side, give control of the query context to the client */
                    stream_ctx->query_ctx = NULL;
                    quicdoq_delete_stream_ctx(cnx_ctx, stream_ctx);
                }
            }
        }
    }

    return ret;
}

/* On the prepare to send callback, provide data */
int quicdoq_callback_prepare_to_send(picoquic_cnx_t* cnx, uint64_t stream_id, quicdoq_stream_ctx_t* stream_ctx,
    void* context, size_t space, quicdoq_cnx_ctx_t* cnx_ctx)
{
    int ret = 0;
    uint8_t* data;
    size_t data_length;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(stream_id);
    UNREFERENCED_PARAMETER(cnx);
#endif

    if (cnx_ctx->is_server) {
        data = stream_ctx->query_ctx->response;
        data_length = stream_ctx->query_ctx->response_length;
    }
    else {
        data = stream_ctx->query_ctx->query;
        data_length = stream_ctx->query_ctx->query_length;
    }

    if (stream_ctx->bytes_sent < data_length){
        uint8_t* buffer;
        size_t available = data_length - stream_ctx->bytes_sent;
        int is_fin = 1;

        if (available > space) {
            available = space;
            is_fin = 0;
        }

        buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
        if (buffer != NULL) {
            memcpy(buffer, data + stream_ctx->bytes_sent, available);
            stream_ctx->bytes_sent += available;
            ret = 0;

            if (is_fin && cnx_ctx->is_server) {
                /* delete the stream context for the server */
                quicdoq_delete_stream_ctx(cnx_ctx, stream_ctx);
            }
        }
        else {
            ret = -1;
        }
    }

    return ret;
}

/* Create a per connection context when a connection is either requested or incoming */

/*
 * DOQ call back.
 *
 * Create a context for each connection.
 * The context holds a list of per stream context, used for managing incoming 
 * and outgoing queries, and a pointer to the DoQ context.
 */

quicdoq_cnx_ctx_t* quicdoq_callback_create_context(quicdoq_ctx_t* quicdoq_ctx, int is_server, picoquic_cnx_t * cnx)
{
    quicdoq_cnx_ctx_t* cnx_ctx = (quicdoq_cnx_ctx_t*)
        malloc(sizeof(quicdoq_cnx_ctx_t));

    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(quicdoq_cnx_ctx_t));
        cnx_ctx->cnx = cnx;
        cnx_ctx->first_stream = NULL;
        cnx_ctx->last_stream = NULL;
        cnx_ctx->quicdoq_ctx = quicdoq_ctx;

        cnx_ctx->previous_cnx = quicdoq_ctx->last_cnx;
        cnx_ctx->next_cnx = NULL;
        if (cnx_ctx->previous_cnx == NULL) {
            quicdoq_ctx->first_cnx = cnx_ctx;
        }
        else {
            cnx_ctx->previous_cnx->next_cnx = cnx_ctx;
        }
        quicdoq_ctx->last_cnx = cnx_ctx;

        cnx_ctx->is_server = is_server;
    }
    return cnx_ctx;
}

void quicdoq_callback_delete_context(quicdoq_cnx_ctx_t* cnx_ctx)
{
    if (cnx_ctx != NULL) {
        /* Remove all streams */
        while (cnx_ctx->first_stream != NULL) {
            quicdoq_delete_stream_ctx(cnx_ctx, cnx_ctx->first_stream);
        }

        /* remove copy of SNI */
        if (cnx_ctx->sni != NULL) {
            free((void*)cnx_ctx->sni);
            cnx_ctx->sni = NULL;
        }

        /* Remove from double linked list in DoQ context */
        if (cnx_ctx->previous_cnx == NULL) {
            cnx_ctx->quicdoq_ctx->first_cnx = cnx_ctx->next_cnx;
        }
        else {
            cnx_ctx->previous_cnx->next_cnx = cnx_ctx->next_cnx;
        }

        if (cnx_ctx->next_cnx == NULL) {
            cnx_ctx->quicdoq_ctx->last_cnx = cnx_ctx->previous_cnx;
        }
        else {
            cnx_ctx->next_cnx->previous_cnx = cnx_ctx->previous_cnx;
        }

        free(cnx_ctx);
    }
}

quicdoq_cnx_ctx_t* quicdoq_find_cnx_ctx(quicdoq_ctx_t* quicdoq_ctx, char const* sni, struct sockaddr* addr)
{
    quicdoq_cnx_ctx_t* cnx_ctx = quicdoq_ctx->first_cnx;

    if (sni != NULL) {
        size_t l_sni = strlen(sni);

        while (cnx_ctx != NULL) {
            if (!cnx_ctx->is_server &&
                picoquic_compare_addr(addr, (struct sockaddr*) & cnx_ctx->addr) == 0 &&
                cnx_ctx->sni != NULL && strlen(cnx_ctx->sni) == l_sni &&
                memcmp(sni, cnx_ctx->sni, l_sni) == 0) {
                /* TODO: manage connection life time */
                break;
            }
        }
    }
    else {
        while (cnx_ctx != NULL) {
            if (!cnx_ctx->is_server &&
                picoquic_compare_addr(addr, (struct sockaddr*) & cnx_ctx->addr) == 0 &&
                cnx_ctx->sni == NULL) {
                /* TODO: manage connection life time */
                break;
            }
        }
    }

    return cnx_ctx;
}

quicdoq_cnx_ctx_t* quicdoq_create_client_cnx(quicdoq_ctx_t* quicdoq_ctx, char const* sni, struct sockaddr* addr)
{
    quicdoq_cnx_ctx_t* cnx_ctx = NULL;
    picoquic_cnx_t* cnx = picoquic_create_cnx(quicdoq_ctx->quic, picoquic_null_connection_id, picoquic_null_connection_id,
        addr, picoquic_get_quic_time(quicdoq_ctx->quic), 0, sni, QUICDOQ_ALPN, 1);
    if (cnx != NULL) {
        cnx_ctx = quicdoq_callback_create_context(quicdoq_ctx, 0, cnx);

        if (cnx_ctx == NULL) {
            picoquic_delete_cnx(cnx);
        }
        else {
            picoquic_store_addr(&cnx_ctx->addr, addr);
            cnx_ctx->sni = picoquic_string_duplicate(sni);
            picoquic_set_callback(cnx, quicdoq_callback, cnx_ctx);

            if (picoquic_start_client_cnx(cnx) != 0) {
                picoquic_connection_id_t cid = picoquic_get_logging_cnxid(cnx);
                DBG_PRINTF("Could not start the connection to %s", sni);
                picoquic_log_app_message(quicdoq_ctx->quic, &cid, "Quicdoq: Could not start the connection to %s.\n", (sni == NULL)?"<NULL>":sni);
                /* TODO: proper error handling */
            }
        }
    }

    return cnx_ctx;
}

/* QuicDoq call back, common to client and server for convenience */

int quicdoq_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    quicdoq_cnx_ctx_t* cnx_ctx = (quicdoq_cnx_ctx_t*)callback_ctx;
    quicdoq_stream_ctx_t* stream_ctx = (quicdoq_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL) {
        /* Unexpected error */
        picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        return -1;
    } else if (cnx_ctx->cnx == NULL){
        /* Only server connections are created this way? */
        cnx_ctx = quicdoq_callback_create_context(cnx_ctx->quicdoq_ctx, 1, cnx);
        if (cnx_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, quicdoq_callback, cnx_ctx);
        }
    }
    else {
        cnx_ctx = (quicdoq_cnx_ctx_t*)callback_ctx;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = quicdoq_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, cnx_ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            quicdoq_callback_delete_context(cnx_ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            /* Should trigger a failure */
            break;
        case picoquic_callback_prepare_to_send:
            ret = quicdoq_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, cnx_ctx);
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

quicdoq_query_ctx_t* quicdoq_create_query_ctx(uint16_t query_max_size, uint16_t response_max_size)
{
    quicdoq_query_ctx_t* query_ctx = (quicdoq_query_ctx_t*)malloc(sizeof(quicdoq_query_ctx_t));

    if (query_ctx != NULL) {
        memset(query_ctx, 0, sizeof(quicdoq_query_ctx_t));
        query_ctx->query = (uint8_t*)malloc(query_max_size);
        query_ctx->response = (uint8_t*)malloc(response_max_size);
        if (query_ctx->query == NULL || query_ctx->response == NULL) {
            quicdoq_delete_query_ctx(query_ctx);
            query_ctx = NULL;
        }
        else {
            query_ctx->query_max_size = query_max_size;
            query_ctx->response_max_size = response_max_size;
        }
    }
    return query_ctx;
}   

void  quicdoq_delete_query_ctx(quicdoq_query_ctx_t* query_ctx)
{
    if (query_ctx->query != NULL) {
        free(query_ctx->query);
        query_ctx->query = NULL;
        query_ctx->query_max_size = 0;
    }
    if (query_ctx->response != NULL) {
        free(query_ctx->response);
        query_ctx->query = NULL;
        query_ctx->response_max_size = 0;
    }
    free(query_ctx);
}

/* Create a quidoq node with the associated context
 */
quicdoq_ctx_t * quicdoq_create(
    char const * cert_file_name, char const * key_file_name, char const * cert_root_file_name,
    char * ticket_store_file_name, char * token_store_file_name,
    quicdoq_app_cb_fn app_cb_fn, void* app_cb_ctx, uint64_t * simulated_time)
{
    quicdoq_ctx_t* quicdoq_ctx = (quicdoq_ctx_t*)malloc(sizeof(quicdoq_ctx_t));
    if (quicdoq_ctx != NULL) {
        uint64_t current_time;

        memset(quicdoq_ctx, 0, sizeof(quicdoq_ctx_t));
        if (simulated_time == NULL) {
            current_time = picoquic_current_time();
        }
        else {
            current_time = *simulated_time;
        }

        quicdoq_ctx->default_callback_ctx.quicdoq_ctx = quicdoq_ctx;
        quicdoq_ctx->app_cb_fn = app_cb_fn;
        quicdoq_ctx->app_cb_ctx = app_cb_ctx;

        quicdoq_ctx->quic = picoquic_create(64, cert_file_name, key_file_name, cert_root_file_name,
            QUICDOQ_ALPN, quicdoq_callback, &quicdoq_ctx->default_callback_ctx, NULL, NULL, NULL, current_time, simulated_time,
            ticket_store_file_name, NULL, 0);

        if (quicdoq_ctx->quic == NULL) {
            quicdoq_delete(quicdoq_ctx);
            quicdoq_ctx = NULL;
        }
        else {
            /* Load the tokens if present. */
            if (token_store_file_name != NULL) {
#if 0
                /* TODO: load tokens API */
                ret = picoquic_load_tokens(quicdoq_ctx->quic->p_first_token, current_time, token_file_name);

                if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
                    DBG_PRINTF("Ticket file <%s> not created yet.\n", ticket_file_name);
                    ret = 0;
                }
                else if (ret != 0) {
                    DBG_PRINTF("Cannot load tickets from <%s>\n", ticket_file_name);
                    ret = 0;
                }
#endif
            }
        }
    }

    return quicdoq_ctx;
}

/* Delete a quicdoq node and the associated context
 */
void quicdoq_delete(quicdoq_ctx_t* ctx)
{
    if (ctx->quic != NULL) {
        picoquic_free(ctx->quic);
        ctx->quic = NULL;
    }

    while (ctx->first_cnx != NULL) {
        quicdoq_callback_delete_context(ctx->first_cnx);
    }

    free(ctx);
}

void quicdoq_set_callback(quicdoq_ctx_t* ctx, quicdoq_app_cb_fn app_cb_fn, void* app_cb_ctx)
{
    ctx->app_cb_fn = app_cb_fn;
    ctx->app_cb_ctx = app_cb_ctx;
}

picoquic_quic_t* quicdoq_get_quic_ctx(quicdoq_ctx_t* ctx)
{
    return ctx->quic;
}

int quicdoq_post_query(quicdoq_ctx_t* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    int ret = 0;
    /* Find whether there already is a connection to the specified address and SNI */
    quicdoq_cnx_ctx_t* cnx_ctx = quicdoq_find_cnx_ctx(quicdoq_ctx, query_ctx->server_name, query_ctx->server_addr);

    if (cnx_ctx == NULL) {
        cnx_ctx = quicdoq_create_client_cnx(quicdoq_ctx, query_ctx->server_name, query_ctx->server_addr);

        if (cnx_ctx == NULL) {
            ret = -1;
        }
        else {
            query_ctx->quic = quicdoq_ctx->quic;
            query_ctx->cid = picoquic_get_logging_cnxid(cnx_ctx->cnx);
        }
    }

    if (ret == 0) {
        /* Pick a stream ID for the query context */
        quicdoq_stream_ctx_t* stream_ctx = quicdoq_find_or_create_stream(
            cnx_ctx->next_available_stream_id, cnx_ctx, 1);
        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            /* Post the data */
            stream_ctx->query_ctx = query_ctx;

            ret = picoquic_mark_active_stream(cnx_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
    }

    return ret;
}

int quicdoq_cancel_query(quicdoq_ctx_t* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx)
{
    if (quicdoq_ctx == NULL || query_ctx == NULL) {
        return -1;
    }
    return 0;
}

int quicdoq_post_response(quicdoq_query_ctx_t* query_ctx)
{
    quicdoq_stream_ctx_t* stream_ctx = (quicdoq_stream_ctx_t*)query_ctx->client_cb_ctx;
    quicdoq_cnx_ctx_t* cnx_ctx = stream_ctx->cnx_ctx;
    picoquic_log_app_message(query_ctx->quic, &query_ctx->cid, "Response #%d received at cnx time: %"PRIu64 "us.\n", query_ctx->query_id, 
        picoquic_get_quic_time(query_ctx->quic) - picoquic_get_cnx_start_time(cnx_ctx->cnx));
    return picoquic_mark_active_stream(cnx_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
}

int quicdoq_cancel_response(quicdoq_ctx_t* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx, uint64_t error_code)
{
    if (quicdoq_ctx == NULL || query_ctx == NULL || error_code != 0) {
        return -1;
    }
    return 0;
}
