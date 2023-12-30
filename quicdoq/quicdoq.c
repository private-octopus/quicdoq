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
        if (cnx_ctx->is_server && stream_ctx->query_ctx != NULL) {
            quicdoq_delete_query_ctx(stream_ctx->query_ctx);
        }
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
    size_t consumed = 0;

    if (cnx_ctx->is_server) {
        if (stream_ctx == NULL) {
            /* Incoming data, server size, requires a context creation */
            stream_ctx = quicdoq_find_or_create_stream(stream_id, cnx_ctx, 1);
            if (stream_ctx == NULL) {
                DBG_PRINTF("Cannot create server context for server stream  #%llu", (unsigned long long)stream_id);
                picoquic_log_app_message(cnx, "Quicdoq: Cannot create server context for server stream  #%llu.\n", (unsigned long long)stream_id);
                ret = -1;
            }
            else {
                /* If this is a server stream, allocate a query structure */
                stream_ctx->query_ctx = quicdoq_create_query_ctx(QUICDOQ_MAX_STREAM_DATA, QUICDOQ_MAX_STREAM_DATA);
                if (stream_ctx->query_ctx == NULL) {
                    DBG_PRINTF("Cannot create query context for server stream  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(cnx, "Quicdoq: Cannot create query context for server stream  #%llu\n", (unsigned long long)stream_id);
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
                    stream_ctx->query_ctx->query_id = cnx_ctx->quicdoq_ctx->next_query_id++;
                    stream_ctx->query_ctx->stream_id = stream_ctx->stream_id;
                }
            }
        }

        if (ret == 0) {
            /* First two bytes of stream are query length. 
             * - must be stored when receiving.
             * - must be compared against max query length. Or should this just always be 64K? 
             * - then shall verify that all bytes are retrieved */
            while (stream_ctx->bytes_received < 2 && consumed < length) {
                stream_ctx->length_received *= 256;
                stream_ctx->length_received += bytes[consumed++];
                stream_ctx->bytes_received++;
            }
            if (length > consumed) {
                /* TODO: maybe allocate data for stated length instead of relying on max_query_size */
                if (stream_ctx->length_received > stream_ctx->query_ctx->query_max_size) {
                    DBG_PRINTF("Incoming query too long for server stream  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(cnx, "Quicdoq: Incoming query too long for server stream  #%llu.\n", (unsigned long long)stream_id);
                    ret = -1;
                }
                else if (stream_ctx->query_ctx->query_length + length - consumed > stream_ctx->length_received) {
                    DBG_PRINTF("Incoming query longer than length for server stream  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(cnx, "Quicdoq: Incoming query longer than length for server stream  #%llu.\n", (unsigned long long)stream_id);
                    ret = -1;
                }
                else {
                    /* Copy incoming data into query context */
                    memcpy(stream_ctx->query_ctx->query + stream_ctx->query_ctx->query_length,
                        bytes + consumed, length - consumed);
                    stream_ctx->query_ctx->query_length += (uint16_t)(length - consumed);

                    if (fin_or_event == picoquic_callback_stream_fin) {
                        /* Query has arrived, verify and then apply the call back */
                        if (stream_ctx->query_ctx->query_length != stream_ctx->length_received) {
                            DBG_PRINTF("Stream FIN before query was received fully on stream  #%llu", (unsigned long long)stream_id);
                            picoquic_log_app_message(cnx, "Quicdoq: Stream FIN before query was received fully on stream  #%llu.\n", (unsigned long long)stream_id);
                            ret = -1;
                        } else  if (stream_ctx->query_ctx->query_length < 2 || stream_ctx->query_ctx->query[0] != 0 || stream_ctx->query_ctx->query[1] != 0) {
                            ret = picoquic_close(cnx, QUICDOQ_ERROR_PROTOCOL);
                        }
                        else {
                            ret = cnx_ctx->quicdoq_ctx->app_cb_fn(quicdoq_incoming_query,
                                cnx_ctx->quicdoq_ctx->app_cb_ctx, stream_ctx->query_ctx,
                                picoquic_get_quic_time(cnx_ctx->quicdoq_ctx->quic));
                        }
                    }
                }
            }
        }
    }
    else {
        if (stream_ctx == NULL) {
            DBG_PRINTF("Data arrived on client stream  #%llu before context creation", (unsigned long long)stream_id);
            picoquic_log_app_message(cnx, "Quicdoq: Data arrived on client stream  #%llu before context creation.\n", (unsigned long long)stream_id);
            ret = -1;
        }
        else {
            while (consumed < length) {
                /* Receive response length */
                while (stream_ctx->bytes_received < 2 && consumed < length) {
                    stream_ctx->length_received *= 256;
                    stream_ctx->length_received += bytes[consumed++];
                    stream_ctx->bytes_received++;
                }
                if (stream_ctx->length_received > stream_ctx->query_ctx->response_max_size) {
                    DBG_PRINTF("Incoming response too long for client stream  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(cnx, "Quicdoq: Incoming response too long for client stream  #%llu.\n", (unsigned long long)stream_id);
                    ret = -1;
                }
                else if (stream_ctx->query_ctx->response_length + length - consumed > stream_ctx->length_received) {
                    /* Another response is stacked after this one. */
                    /* Finish receiving the current response */
                    size_t to_be_consumed = stream_ctx->length_received - stream_ctx->query_ctx->response_length - (length - consumed);
                    memcpy(stream_ctx->query_ctx->response + stream_ctx->query_ctx->response_length,
                        bytes + consumed, to_be_consumed);
                    consumed += to_be_consumed;
                    /* then signal a partial response */
                    ret = cnx_ctx->quicdoq_ctx->app_cb_fn(quicdoq_response_partial,
                        cnx_ctx->quicdoq_ctx->app_cb_ctx, stream_ctx->query_ctx,
                        picoquic_get_quic_time(cnx_ctx->quicdoq_ctx->quic));
                    /* then reset the receive state */
                    stream_ctx->query_ctx->response_length = 0;
                    stream_ctx->length_received = 0;
                }
                else {
                    /* Copy incoming data into query context */
                    memcpy(stream_ctx->query_ctx->response + stream_ctx->query_ctx->response_length,
                        bytes + consumed, length - consumed);
                    stream_ctx->query_ctx->response_length += (uint16_t)(length - consumed);
                    consumed = length;
                }
            }
            
            if (fin_or_event == picoquic_callback_stream_fin) {
                if (stream_ctx->length_received < 2 || stream_ctx->length_received != stream_ctx->query_ctx->response_length) {
                    DBG_PRINTF("Client stream closed before final response  #%llu", (unsigned long long)stream_id);
                    picoquic_log_app_message(cnx, "Quicdoq: client stream closed before final response  #%llu.\n", (unsigned long long)stream_id);
                    ret = -1;
                } else {
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
    size_t already_sent = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(stream_id);
    UNREFERENCED_PARAMETER(cnx);
#endif
    /* TODO: this code assumes a single response per query. In order
     * to support XFR and AXFR, need a way to push several responses */
    if (cnx_ctx->is_server) {
        data = stream_ctx->query_ctx->response;
        data_length = stream_ctx->query_ctx->response_length;
    }
    else {
        data = stream_ctx->query_ctx->query;
        data_length = stream_ctx->query_ctx->query_length;
    }

    if (stream_ctx->bytes_sent < data_length + 2) {
        uint8_t* buffer;
        size_t available = data_length + 2 - stream_ctx->bytes_sent;
        int is_fin = 1;

        if (available > space) {
            available = space;
            is_fin = 0;
        }
        buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
        if (buffer != NULL) {
            while (stream_ctx->bytes_sent < 2 && already_sent < space) {
                buffer[already_sent] = (stream_ctx->bytes_sent == 0) ? ((uint8_t)(data_length >> 8)) : ((uint8_t)(data_length & 0xff));
                stream_ctx->bytes_sent++;
                already_sent++;
            }
            if (already_sent < space) {
                memcpy(buffer + already_sent, data + stream_ctx->bytes_sent - 2, available - already_sent);
                stream_ctx->bytes_sent += available - already_sent;
                ret = 0;
            }

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

            quicdoq_set_tp(cnx);

            if (picoquic_start_client_cnx(cnx) != 0) {
                DBG_PRINTF("Could not start the connection to %s", sni);
                picoquic_log_app_message(cnx, "Quicdoq: Could not start the connection to %s.\n", (sni == NULL)?"<NULL>":sni);
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
            ret = cnx_ctx->quicdoq_ctx->app_cb_fn(quicdoq_response_cancelled,
                cnx_ctx->quicdoq_ctx->app_cb_ctx, stream_ctx->query_ctx,
                picoquic_get_quic_time(cnx_ctx->quicdoq_ctx->quic));
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
            if (quicdoq_check_tp(cnx_ctx, cnx) != 0) {
                (void)picoquic_close(cnx, QUICDOQ_ERROR_PROTOCOL);
            }
            break;
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

/* Set transport parameters to adequate value for quicdoq server.
 */
int quicdoq_set_default_tp(quicdoq_ctx_t* quicdoq_ctx)
{
    int ret = 0;
    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(picoquic_tp_t));
    /* This is a server context. The "remote" bidi streams are those
        * initiated by the client, and should be authorized to send
        * a 64K-1 packet */
    tp.initial_max_stream_data_bidi_local = 0;
    tp.initial_max_stream_data_bidi_remote = QUICDOQ_MAX_STREAM_DATA;
    tp.initial_max_stream_id_bidir = 256;
    tp.initial_max_stream_data_uni = 0;
    tp.initial_max_data = 0x10000;
    tp.initial_max_stream_id_unidir = 0;
    tp.max_idle_timeout = 20000;
    tp.max_packet_size = 1232;
    tp.max_ack_delay = 10000;
    tp.active_connection_id_limit = 3;
    tp.ack_delay_exponent = 3;
    tp.migration_disabled = 0;
    /* tp.prefered_address: todo, consider use of preferred address for anycast server */
    /* all optional parameters set to zero */
    ret = picoquic_set_default_tp(quicdoq_ctx->quic, &tp);
    return ret;
}

/* Set transport parameters to adequate value for quicdoq client.
 */
void quicdoq_set_tp(picoquic_cnx_t * cnx)
{
    picoquic_tp_t tp;
    memset(&tp, 0, sizeof(picoquic_tp_t));
    /* This is a client context. The "local" bidi streams are those
        * initiated by the client, and the server should be authorized to send
        * a 64K-1 packet */
    tp.initial_max_stream_data_bidi_local = QUICDOQ_MAX_STREAM_DATA;
    tp.initial_max_stream_data_bidi_remote = 0;
    tp.initial_max_stream_id_bidir = 0;
    tp.initial_max_stream_data_uni = 0;
    tp.initial_max_data = 0x10000;
    tp.initial_max_stream_id_unidir = 0;
    tp.max_idle_timeout = 20000;
    tp.max_packet_size = 1232;
    tp.max_ack_delay = 10000;
    tp.active_connection_id_limit = 3;
    tp.ack_delay_exponent = 3;
    tp.migration_disabled = 0;
    /* tp.prefered_address: todo, consider use of preferred address for anycast server */
    /* all optional parameters set to zero */
    picoquic_set_transport_parameters(cnx, &tp);
}

/* Verify that transport parameters have the expected value */
int quicdoq_check_tp(quicdoq_cnx_ctx_t* cnx_ctx, picoquic_cnx_t* cnx)
{
    int ret = 0;
    picoquic_tp_t const* tp = picoquic_get_transport_parameters(cnx, 0);

    if (cnx_ctx->is_server) {
        if (tp->initial_max_stream_data_bidi_local < QUICDOQ_MAX_STREAM_DATA)
        {
            picoquic_log_app_message(cnx, "Recive max stream bidir local < 65635: 0x%" PRIx64, tp->initial_max_stream_data_bidi_local);
        }
    }
    else {
        if (tp->initial_max_stream_data_bidi_remote < QUICDOQ_MAX_STREAM_DATA)
        {
            picoquic_log_app_message(cnx, "Recive max stream bidir remote < 65635: 0x%" PRIx64, tp->initial_max_stream_data_bidi_remote);
        }
    }

    return ret;
}

/* Create a quidoq node with the associated context
 */
quicdoq_ctx_t * quicdoq_create(char const * alpn,
    char const * cert_file_name, char const * key_file_name, char const * cert_root_file_name,
    char const * ticket_store_file_name, char const * token_store_file_name,
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
        if (alpn == NULL) {
            alpn = QUICDOQ_ALPN;
        }

        quicdoq_ctx->quic = picoquic_create(64, cert_file_name, key_file_name, cert_root_file_name,
            alpn, quicdoq_callback, &quicdoq_ctx->default_callback_ctx, NULL, NULL, NULL, current_time, simulated_time,
            ticket_store_file_name, NULL, 0);

        if (quicdoq_ctx->quic == NULL) {
            quicdoq_delete(quicdoq_ctx);
            quicdoq_ctx = NULL;
        }
        else {
            if (quicdoq_set_default_tp(quicdoq_ctx) != 0) {
                DBG_PRINTF("%s", "Could not set default transport parameters.");
            }
            /* Load the tokens if present. */
            if (token_store_file_name != NULL) {
                int ret = picoquic_load_retry_tokens(quicdoq_ctx->quic, token_store_file_name);

                if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
                    DBG_PRINTF("Ticket file <%s> not created yet.\n", token_store_file_name);
                }
                else if (ret != 0) {
                    DBG_PRINTF("Cannot load tickets from <%s>\n", token_store_file_name);
                }
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
    }

    if (ret == 0) {
        /* Pick a stream ID for the query context */
        quicdoq_stream_ctx_t* stream_ctx = quicdoq_find_or_create_stream(
            cnx_ctx->next_available_stream_id, cnx_ctx, 1);
        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            /* Mark the stream as used, update the context, post the data */
            cnx_ctx->next_available_stream_id += 4;
            stream_ctx->query_ctx = query_ctx;
            query_ctx->stream_id = stream_ctx->stream_id;
            query_ctx->cid = picoquic_get_logging_cnxid(cnx_ctx->cnx);
            query_ctx->quic = quicdoq_ctx->quic;


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
    picoquic_log_app_message(cnx_ctx->cnx, "Response #%d received at cnx time: %"PRIu64 "us.\n", query_ctx->query_id, 
        picoquic_get_quic_time(query_ctx->quic) - picoquic_get_cnx_start_time(cnx_ctx->cnx));
    return picoquic_mark_active_stream(cnx_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
}


int quicdoq_format_refuse_response(
    uint8_t* query, size_t query_length,
    uint8_t* response, size_t response_max_size, size_t* response_length,
    uint16_t extended_dns_error)
{
    int ret = -1;

    if (query_length <= (size_t)response_max_size && query_length > 12) {
        /* Find the length of all queries */
        int nb_queries = query[4] * 256 + query[5];
        size_t after_q = 12;
        size_t r_len = 0;
        for (int q_index = 0; q_index < nb_queries && after_q < query_length; q_index++) {
            /* Parse the DNS query to find the end of the first query */
            after_q = quicdoq_skip_dns_name(query, query_length, after_q);
            if (after_q + 4 <= query_length) {
                after_q += 4;
                ret = 0;
            }
            else {
                after_q = query_length;
                ret = -1;
                break;
            }
        }
        if (ret == 0) {
            /* Copy the query into the response */
            memcpy(response, query, after_q);
            /* Set the QR bit to 1 */
            response[2] |= 128;
            /* Set the response code to refused */
            response[3] = (query[3] & 0xF0) | 5;
            /* Set the AN, NS, AD counts to 0 */
            memset(response + 6, 0, 6);
            r_len = after_q;
            /* If the query might have included OPT and there is room, add an OPT RR */
            if (r_len < query_length && r_len + 15 <= response_max_size) {
                /* Set AD count to 1 */
                response[11] = 1;
                /* Format OPT
                 * Field Name 	Field Type 	Description
                 * NAME     domain name  MUST be 0 (root domain)
                 * TYPE     u_int16_t    OPT (41)
                 * CLASS    u_int16_t    requestor's UDP payload size
                 * TTL      u_int32_t    extended RCODE and flags
                 * RDLEN    u_int16_t    length of all RDATA
                 * RDATA 	octet stream {attribute,value} pairs
                 * -- Option 15 (EDE), L(2), 16 bits
                 */
                response[r_len++] = 0; /* NAME */
                response[r_len++] = 0; response[r_len++] = 41; /* TYPE OPT */
                response[r_len++] = 0xff; response[r_len++] = 0xff; /* payload size 0xFFFF */
                response[r_len++] = 0; /* Not using extended r_code */
                response[r_len++] = 0; /* EDNS version */
                response[r_len++] = 0; response[r_len++] = 0; /* Flags = 0 */
                response[r_len++] = 0; response[r_len++] = 4; /* RDLEN = 4 */
                response[r_len++] = 15; /* EDE */
                response[r_len++] = 2; /* L = 2 */
                response[r_len++] = (uint8_t)(extended_dns_error >> 8); /* EDE, MSB */
                response[r_len++] = (uint8_t)(extended_dns_error & 0xFF); /* EDE, LSB */
            }
            /* Success */
            *response_length = r_len;
            ret = 0;
        }
    }

    return ret;
}

int quicdoq_refuse_response(quicdoq_ctx_t* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx, uint16_t extended_dns_error)
{
    int ret = 0;
    if (quicdoq_ctx == NULL || query_ctx == NULL) {
        ret = -1;
    }
    else {
        quicdoq_stream_ctx_t* stream_ctx = (quicdoq_stream_ctx_t*)query_ctx->client_cb_ctx;
        quicdoq_cnx_ctx_t* cnx_ctx = stream_ctx->cnx_ctx;
        /* Store the response */
        ret = quicdoq_format_refuse_response(query_ctx->query, query_ctx->query_length, query_ctx->response,
            query_ctx->response_max_size, &query_ctx->response_length, extended_dns_error);
        if (ret == 0) {
            picoquic_log_app_message(cnx_ctx->cnx, "Query #%d refused with EDE 0x%x at cnx time: %"PRIu64 "us.\n", 
                query_ctx->query_id, extended_dns_error, picoquic_get_quic_time(query_ctx->quic) - picoquic_get_cnx_start_time(cnx_ctx->cnx));
            return picoquic_mark_active_stream(cnx_ctx->cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
    }

    return ret;
}

int quicdoq_cancel_response(quicdoq_ctx_t* quicdoq_ctx, quicdoq_query_ctx_t* query_ctx, uint16_t error_code)
{
    int ret = 0;
    if (quicdoq_ctx == NULL || query_ctx == NULL) {
        ret = -1;
    } else {
        quicdoq_stream_ctx_t* stream_ctx = (quicdoq_stream_ctx_t*)query_ctx->client_cb_ctx;
        quicdoq_cnx_ctx_t* cnx_ctx = stream_ctx->cnx_ctx;
        ret = picoquic_reset_stream(cnx_ctx->cnx, stream_ctx->stream_id, error_code);
    }

    return ret;
}

int quicdoq_is_closed(quicdoq_ctx_t* quicdoq_ctx)
{
    quicdoq_cnx_ctx_t* cnx_ctx = quicdoq_ctx->first_cnx;
    int is_empty = 1;

    while (cnx_ctx != NULL) {
        is_empty &= picoquic_is_cnx_backlog_empty(cnx_ctx->cnx);
        if (!is_empty) {
            break;
        }
        else {
            picoquic_state_enum cnx_state = picoquic_get_cnx_state(cnx_ctx->cnx);
            if (cnx_state < picoquic_state_disconnecting) {
                picoquic_close(cnx_ctx->cnx, 0);
                is_empty = 0;
                break;
            }
            else if (cnx_state != picoquic_state_disconnected) {
                is_empty = 0;
                break;
            }
            cnx_ctx = cnx_ctx->next_cnx;
        }
    }
    return is_empty;
}
