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

#ifdef _WINDOWS
#ifdef _WINDOWS64
#define QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\picoquic\\"
#else
#define QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\picoquic\\"
#endif
#else
#define QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR "../picoquic/"
#endif

char const* quicdoq_test_picoquic_solution_dir = QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR;


/* End to end test of Quicdoq
* Set a network with two DoQ nodes : client and server.
* The network uses the picoquic simulation infrastructure,
* in a single threaded implementation.
* The client runs through a query scenario, i.e. a list
* of names to resolve.
* The server has an automated response, based on the
* names: either immediate, or delayed.
* Each test will verify that the connection is established properly,
* and then verify that the basic scenario work, before closing
* the client first and then the server.
*/

/* Scenario description.
* The client will submit a set of simulated queries.
* For this simulation, we will rely on automated responses produced at
* the test server, and the QType and RType will alway be 1 and 0. The
* response will always be "A 10.0.0.1".
* For each query, we specify a schedule time, the time at which the
* query is submitted.
*
* Each query is defined by:
*  - a query id, i.e. the rank of the query in the scenario description.
*  - an expected result: success or cancel.
*  - the simulated delay at the server.
*
* The query_id is encoded as DNS Query ID, in the first 2 bytes of
* the DNS query. The name is arbitrary. We set it to "nnn.example.com",
* where nnn is the query ID, but this is not tested.
*
* The results of execution are held in a scenario record.
*
* The server will retrieve the entry, document the arrival time,
* and schedule execution per expected result and delay.
*
* The client will record the time at which a response is received
* in the scenario entry, as well as the result.
*/

typedef struct st_quicdoq_test_scenario_entry_t {
    uint64_t schedule_time;
    uint64_t response_delay;
    int is_success;
} quicdoq_test_scenario_entry_t;

typedef struct st_quicdoq_test_scenario_record_t {
    uint64_t query_sent_time;
    uint64_t query_arrival_time;
    uint64_t response_sent_time;
    uint64_t response_arrival_time;
    quicdoq_query_ctx_t* queued_response;
    int query_sent;
    int query_received;
    int server_error;
    int response_received;
    int cancel_received;
    int is_success;
} quicdoq_test_scenario_record_t;


/* Text context, holding all the state of the ongoing simulation */
typedef struct st_quicdog_test_ctx_t {
    uint64_t simulated_time;
    quicdoq_ctx_t* qd_client;
    quicdoq_ctx_t* qd_server;
    struct sockaddr_storage server_addr;
    struct sockaddr_storage client_addr;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquictest_sim_link_t* server_link;
    picoquictest_sim_link_t* client_link;
    uint16_t nb_scenarios;
    quicdoq_test_scenario_entry_t const* scenario;
    quicdoq_test_scenario_record_t* record;
    uint64_t next_query_time;
    uint64_t next_response_time;
    uint16_t next_query_id;
    uint16_t next_response_id;
    int all_query_served;
} quicdog_test_ctx_t;

/* Server call back for tests
 */
uint16_t quicdog_test_get_query_id(quicdoq_query_ctx_t* query_ctx)
{
    uint16_t qid = UINT16_MAX;

    if (query_ctx != NULL && query_ctx->query != NULL && query_ctx->query_length >= 2) {
        qid = (query_ctx->query[0] << 8) | query_ctx->query[1];
    }

    return qid;
}

int quicdog_test_get_format_response(quicdoq_query_ctx_t* query_ctx)
{
    int ret = -1;
    const uint8_t rr_a[] = { 0xC0, 12, 0, 1, 0, 0, 0, 4, 0, 0, 32, 0, 10, 0, 0, 1 };
    uint16_t qtype = UINT16_MAX;
    uint16_t qclass = UINT16_MAX;

    if (sizeof(rr_a) + query_ctx->query_length <= (size_t)query_ctx->response_max_size && query_ctx->query_length > 12) {
        /* Parse the DNS query to find the end of the first query */
        uint16_t after_q = (uint16_t)quicdoq_skip_dns_name(query_ctx->query, query_ctx->query_length, 12);
        if (after_q + 4 <= query_ctx->query_length) {
            qtype = (query_ctx->query[after_q] << 8) | query_ctx->query[after_q + 1];
            qclass = (query_ctx->query[after_q + 2] << 8) | query_ctx->query[after_q + 3];
            after_q += 4;
        }
        if (qtype == 1 && qclass == 0) {
            /* Insert the RR between query and EDNS */
            memcpy(query_ctx->response, query_ctx->query, after_q);
            query_ctx->response_length = (uint16_t)after_q;
            memcpy(query_ctx->response + query_ctx->response_length, rr_a, sizeof(rr_a));
            query_ctx->response_length += (uint16_t)sizeof(rr_a);
            memcpy(query_ctx->response + query_ctx->response_length, query_ctx->query + after_q, query_ctx->query_length - after_q);
            query_ctx->response_length += query_ctx->query_length - after_q;
            /* Set the QR bit to 1 */
            query_ctx->response[2] |= 128;
            /* Set the AN count to 1 */
            query_ctx->response[7] = 0;
            /* Success! */
            ret = 0;
        }
    }

    return ret;
}

void quicdoq_set_response_queue(quicdog_test_ctx_t* ctx, uint16_t qid)
{
    uint64_t r_time = ctx->record[qid].query_arrival_time;
    if (ctx->record[qid].queued_response->response_length > 0) {
        r_time += ctx->scenario[qid].response_delay;
    }
    if (r_time < ctx->next_response_time) {
        ctx->next_response_time = r_time;
        ctx->next_response_id = qid;
    }
}

void quicdoq_reset_response_queue(quicdog_test_ctx_t* ctx)
{
    ctx->next_response_id = ctx->nb_scenarios;
    ctx->next_response_time = UINT64_MAX;

    for (uint16_t qid = 0; qid < ctx->nb_scenarios; qid++) {
        if (ctx->record[qid].query_received && ctx->record[qid].queued_response != NULL) {
            quicdoq_set_response_queue(ctx, qid);
        }
    }
}

int quicdoq_test_server_cb(
    quicdoc_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdog_test_ctx_t* ctx = (quicdog_test_ctx_t*)callback_ctx;
    uint16_t qid = quicdog_test_get_query_id(query_ctx);

    switch (callback_code) {
    case quicdoq_incoming_query: /* Incoming callback query */
        if (qid > ctx->nb_scenarios || ctx->record[qid].query_received) {
            ret = -1;
        }
        else {
            ctx->record[qid].query_arrival_time = ctx->simulated_time;
            ctx->record[qid].query_received = 1;
            /* queue the response */
            if (!ctx->scenario[qid].is_success ||
                quicdog_test_get_format_response(query_ctx) != 0) {
                query_ctx->response_length = 0; /* This will trigger a cancellation */
            }
            ctx->record[qid].queued_response = query_ctx;
            quicdoq_set_response_queue(ctx, qid);
        }
        break;
    case quicdoq_query_cancelled: /* Query cancelled before response provided */
    case quicdoq_query_failed: /* Query failed for reasons other than cancelled. */
        /* remove response from queue, mark it cancelled */
        if (qid > ctx->nb_scenarios || !ctx->record[qid].query_received || ctx->record[qid].queued_response) {
            ret = -1;
        }
        else {
            ctx->record[qid].queued_response = NULL;
            ctx->record[qid].response_sent_time = ctx->simulated_time;
            ctx->record[qid].server_error = 1;
        }
        quicdoq_reset_response_queue(ctx);
        break;
    default: /* callback code not expected on server */
        ret = -1;
        break;
    }

    return ret;
}

int quicdoq_test_server_submit_response(quicdog_test_ctx_t* ctx)
{
    int ret = 0;

    /* Check whether the next query is ready */
    if (ctx->next_response_id >= ctx->nb_scenarios ||
        ctx->record[ctx->next_response_id].queued_response == NULL) {
        ret = -1;
    }
    else {
        /* submit the response */
        if (ctx->record[ctx->next_response_id].queued_response->response_length > 0) {
            ret = quicdoq_post_response(ctx, ctx->record[ctx->next_response_id].queued_response);
        }
        else {
            ret = quicdoq_cancel_response(ctx, ctx->record[ctx->next_response_id].queued_response);
        }
        ctx->record[ctx->next_response_id].queued_response = NULL;
        ctx->record[ctx->next_response_id].response_sent_time = ctx->simulated_time;

        quicdoq_reset_response_queue(ctx);
    }

    return ret;
}

/* Client call back and submit function for tests
 */

int quicdoq_test_client_cb(
    quicdoc_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdog_test_ctx_t* ctx = (quicdog_test_ctx_t*)callback_ctx;
    uint16_t qid = quicdog_test_get_query_id(query_ctx);

    if (qid > ctx->nb_scenarios) {
        ret = -1;
    } if (ctx->record[qid].response_received) {
        ret = -1;
    }
    else {
        ctx->record[qid].response_received = 1;
        ctx->record[qid].response_arrival_time = ctx->simulated_time;

        switch (callback_code) {
        case quicdoq_response_complete: /* The response to the current query arrived. */
            /* tabulate completed */
            ctx->record[qid].is_success = 1;
            break;
        case quicdoq_response_cancelled: /* The response to the current query was cancelled by the peer. */
            ctx->record[qid].cancel_received = 1;
            /* tabulate cancelled */
        case quicdoq_query_failed:  /* Query failed for reasons other than cancelled. */
            /* tabulate failed */
            break;
        default: /* callback code not expected on client */
            ret = -1;
            break;
        }

        /* Check whether there are still responses pending. */
        ctx->all_query_served = 1;
        for (uint16_t i = 0; i < ctx->nb_scenarios; i++) {
            if (!ctx->record[i].response_received) {
                ctx->all_query_served = 0;
                break;
            }
        }
    }

    if (ret == 0 && query_ctx != NULL) {
        /* free the query element */
        quicdoq_delete_query_ctx(query_ctx);
    }

    return ret;
}

int quicdoq_test_client_submit_query(quicdog_test_ctx_t* ctx)
{
    int ret = 0;
    quicdoq_query_ctx_t* query_ctx = NULL;

    /* Check whether the next query is ready */
    if (ctx->next_query_id >= ctx->nb_scenarios ||
        ctx->scenario[ctx->next_query_id].schedule_time < ctx->simulated_time ||
        ctx->record[ctx->next_query_id].query_sent) {
        ret = -1;
    }
    else {
        /* create a query record */
        quicdoq_query_ctx_t* query_ctx = quicdoq_create_query_ctx(512, 1024);
    }

    if (query_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* fill the query and address parts of the query context */
        char name_buf[256];
        size_t name_length = 0;
        uint8_t* qbuf = query_ctx->query;
        uint8_t* qbuf_max = query_ctx->query + query_ctx->query_max_size;

        (void)picoquic_sprintf(name_buf, sizeof(name_buf), &name_length, "%d.example.com", ctx->next_query_id);
        qbuf = quicdog_format_dns_query(qbuf, qbuf_max, name_buf, ctx->next_query_id, 0, 1, query_ctx->response_max_size);
        if (qbuf == NULL) {
            ret = -1;
        }
        else {
            query_ctx->query_length = (uint16_t)(qbuf - query_ctx->query);

            query_ctx->server_name = PICOQUIC_TEST_SNI;
            query_ctx->client_addr = (struct sockaddr*) & ctx->client_addr;
            query_ctx->server_addr = (struct sockaddr*) & ctx->server_addr;
            query_ctx->client_cb = quicdoq_test_client_cb;
            query_ctx->client_cb_ctx = ctx;

            ret = quicdoq_post_query(ctx->qd_client, query_ctx);
        }
    }

    /* Set the context for the next query after that */
    if (ret == 0) {
        ctx->next_query_id++;
        if (ctx->next_query_id >= ctx->nb_scenarios) {
            ctx->next_query_time = UINT64_MAX;
        }
        else {
            ctx->next_query_time = ctx->scenario[ctx->next_query_id].schedule_time;
        }
    }
    else {
        if (query_ctx != NULL) {
            quicdoq_delete_query_ctx(query_ctx);
        }
    }

    return ret;
}

/* Test context create and delete
 */

void quicdoq_test_ctx_delete(quicdog_test_ctx_t* ctx)
{
    if (ctx->qd_client != NULL) {
        quicdoq_delete(ctx->qd_client);
        ctx->qd_client = NULL;
    }

    if (ctx->qd_server != NULL) {
        quicdoq_delete(ctx->qd_server);
        ctx->qd_server = NULL;
    }

    if (ctx->client_link != NULL) {
        picoquictest_sim_link_delete(ctx->client_link);
        ctx->client_link = NULL;
    }

    if (ctx->server_link != NULL) {
        picoquictest_sim_link_delete(ctx->server_link);
        ctx->server_link = NULL;
    }

    free(ctx);
}

quicdog_test_ctx_t* quicdoq_test_ctx_create(quicdoq_test_scenario_entry_t const * scenario, size_t size_of_scenario)
{
    quicdog_test_ctx_t* ctx = (quicdog_test_ctx_t*)malloc(sizeof(quicdog_test_ctx_t));

    if (ctx != NULL) {
        int ret = 0;
        memset(ctx, 0, sizeof(quicdog_test_ctx_t));
        /* Locate the default cert, key and root in the Picoquic solution*/
        ret = picoquic_get_input_path(ctx->test_server_cert_file, sizeof(ctx->test_server_cert_file), 
            quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(ctx->test_server_key_file, sizeof(ctx->test_server_key_file), 
                quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            ret = picoquic_get_input_path(ctx->test_server_cert_store_file, sizeof(ctx->test_server_cert_store_file), 
                quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
        }

        /* Set test addresses for client and server */
        if (ret == 0) {
            ret = picoquic_store_text_addr(&ctx->server_addr, "1::1", 443);
        }

        if (ret == 0) {
            ret = picoquic_store_text_addr(&ctx->client_addr, "2::2", 12345);
        }

        /* create the client and server contexts */
        ctx->qd_server = quicdoq_create(quicdoq_test_server_cb, (void*) ctx,
            NULL, NULL, ctx->test_server_cert_store_file, &ctx->simulated_time);
        ctx->qd_client = quicdoq_create(quicdoq_test_client_cb, (void*)ctx,
            ctx->test_server_cert_file, ctx->test_server_key_file, NULL, &ctx->simulated_time);


        /* Create the simulation links */
        ctx->server_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        ctx->client_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

        /* Insert the scenarios */
        ctx->nb_scenarios = (uint16_t)(size_of_scenario / sizeof(quicdoq_test_scenario_entry_t));
        ctx->scenario = scenario;
        ctx->record = (quicdoq_test_scenario_record_t*)malloc(ctx->nb_scenarios * sizeof(quicdoq_test_scenario_record_t));
        if (ctx->record != NULL) {
            memset(ctx->record, 0, ctx->nb_scenarios * sizeof(quicdoq_test_scenario_record_t));
        }
        ctx->next_query_time = ctx->scenario[0].schedule_time;
        ctx->next_response_time = UINT64_MAX;
        if (ret != 0 || ctx->qd_client == NULL || ctx->qd_server == NULL ||
            ctx->server_link == NULL || ctx->client_link == NULL || ctx->record == NULL) {
            quicdoq_test_ctx_delete(ctx);
            ctx = NULL;
        }

    }
    return ctx;
}

int quicdoq_test_sim_packet_input(quicdog_test_ctx_t* ctx, picoquic_quic_t* quic, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;
        ret = picoquic_incoming_packet(quic, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*) & packet->addr_from,
            (struct sockaddr*) & packet->addr_to, 0, 0,
            ctx->simulated_time);
        free(packet);
    }

    return ret;
}

int quicdoq_test_sim_packet_prepare(quicdog_test_ctx_t* ctx, picoquic_quic_t* quic, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    int peer_addr_len = 0;
    int local_addr_len = 0;

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(quic, ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &peer_addr_len, &packet->addr_from, &local_addr_len, &if_index);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            ret = -1;
        }
    }

    /* TODO: check that dest and srce address are what is expected */

    if (ret == 0 && packet->length > 0) {
        *is_active = 1;
        picoquictest_sim_link_submit(link, packet, ctx->simulated_time);
    } else {
        free(packet);
    }

    return ret;
}

int quicdoq_test_sim_step(quicdog_test_ctx_t* ctx, int * is_active)
{
    int ret = 0;
    uint64_t next_time = UINT64_MAX;
    uint64_t try_time;
    int next_step = -1;

    *is_active = 0;

    if ((try_time = picoquic_get_next_wake_time(ctx->qd_client->quic, ctx->simulated_time)) < next_time) {
        next_time = try_time;
        next_step = 0;
    }

    if ((try_time = picoquic_get_next_wake_time(ctx->qd_server->quic, ctx->simulated_time)) < next_time) {
        next_time = try_time;
        next_step = 1;
    }

    if (ctx->client_link->first_packet != NULL &&
        ctx->client_link->first_packet->arrival_time < next_time) {
        next_time = ctx->client_link->first_packet->arrival_time;
        next_step = 2;
    }

    if (ctx->server_link->first_packet != NULL &&
        ctx->server_link->first_packet->arrival_time < next_time) {
        next_time = ctx->server_link->first_packet->arrival_time;
        next_step = 3;
    }

    if (ctx->next_query_time < next_time) {
        next_time = ctx->next_query_time;
        next_step = 4;
    }

    if (ctx->next_response_time < next_time) {
        next_time = ctx->next_response_time;
        next_step = 5;
    }

    /* Update the virtual time */
    if (next_time > ctx->simulated_time) {
        ctx->simulated_time = next_time;
    }

    /* Execute the most urgent action. */
    switch (try_time) {
    case 0:
        ret = quicdoq_test_sim_packet_prepare(ctx, ctx->qd_client->quic, ctx->server_link, is_active);
        break;
    case 1:
        ret = quicdoq_test_sim_packet_prepare(ctx, ctx->qd_server->quic, ctx->client_link, is_active);
        break;
    case 2:
        ret = quicdoq_test_sim_packet_input(ctx, ctx->qd_client->quic, ctx->client_link, is_active);
        break;
    case 3:
        ret = quicdoq_test_sim_packet_input(ctx, ctx->qd_server->quic, ctx->server_link, is_active);
        break;
    case 4:

    /* TODO: per scenario actions */
    default:
        /* Nothing to do, which is unlikely since the server is always up. */
        ret = -1;
        break;
    }

    return ret;
}

int quicdoq_test_sim_run(quicdog_test_ctx_t* ctx, uint64_t time_limit)
{
    int ret = 0;
    int is_active = 0;
    int inactive_count = 0;

    while (ret == 0 && !ctx->all_query_served && inactive_count < 1204 && ctx->simulated_time < time_limit) {
        ret = quicdoq_test_sim_step(ctx, &is_active);

        if (is_active) {
            inactive_count = 0;
        }
        else {
            inactive_count++;
        }
    }

    return ret;
}

/* Basic scenario: just one query, immediate positive response */
static quicdoq_test_scenario_entry_t const basic_scenario[] = {
    { 0, 0, 1 }
};

int quicdoq_basic_test()
{
    quicdog_test_ctx_t* ctx = quicdoq_test_ctx_create(basic_scenario, sizeof(basic_scenario));
    int ret = 0;

    if (ctx == NULL) {
        ret = -1;
    }
    else {
        ret = quicdoq_test_sim_run(ctx, 3000000);

        if (ret != 0 || !ctx->all_query_served) {
            DBG_PRINTF("Fail after %llu, all_served=%d, ret=%d",
                (unsigned long long)ctx->simulated_time, ctx->all_query_served, ret);
            ret = -1;
        }
        quicdoq_test_ctx_delete(ctx);
    }

    return ret;
}