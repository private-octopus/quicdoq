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
#define QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\..\\picoquic\\"
#else
#define QUICDOQ_PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\picoquic\\"
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
    picoquictest_sim_packet_t* queued_packet;
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
    quicdoq_udp_ctx_t* udp_ctx;
    struct sockaddr_storage server_addr;
    struct sockaddr_storage client_addr;
    struct sockaddr_storage udp_addr;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquictest_sim_link_t* server_link;
    picoquictest_sim_link_t* client_link;
    picoquictest_sim_link_t* udp_link_out;
    picoquictest_sim_link_t* udp_link_in;
    uint16_t nb_scenarios;
    quicdoq_test_scenario_entry_t const* scenario;
    quicdoq_test_scenario_record_t* record;
    uint64_t next_query_time;
    uint64_t next_response_time;
    uint16_t next_query_id;
    uint16_t next_response_id;
    int all_query_served;
    int some_query_inconsistent;
    int some_query_failed;
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

int quicdog_test_get_format_response(
    uint8_t * query, size_t query_length, 
    uint8_t * response, size_t response_max_size, size_t * response_length)
{
    int ret = -1;
    const uint8_t rr_a[] = { 0xC0, 12, 0, 1, 0, 0, 0, 4, 0, 0, 32, 0, 10, 0, 0, 1 };
    uint16_t qtype = UINT16_MAX;
    uint16_t qclass = UINT16_MAX;

    if (sizeof(rr_a) + query_length <= (size_t) response_max_size && query_length > 12) {
        /* Parse the DNS query to find the end of the first query */
        size_t after_q = quicdoq_skip_dns_name(query, query_length, 12);
        if (after_q + 4 <= query_length) {
            qtype = (query[after_q] << 8) | query[after_q + 1];
            qclass = (query[after_q + 2] << 8) | query[after_q + 3];
            after_q += 4;
        }

        if (qtype == 1 && qclass == 0) {
            uint16_t r_index = 0;
            /* Insert the RR between query and EDNS */
            memcpy(response, query, after_q);
            r_index = (uint16_t)after_q;
            memcpy(response + r_index, rr_a, sizeof(rr_a));
            r_index += (uint16_t)sizeof(rr_a);
            memcpy(response + r_index, query + after_q, query_length - after_q);
            *response_length = query_length + sizeof(rr_a);
            /* Set the QR bit to 1 */
            response[2] |= 128;
            /* Set the AN count to 1 */
            response[7] = 1;
            /* Success! */
            ret = 0;
        }
    }

    return ret;
}

void quicdoq_set_test_response_queue(quicdog_test_ctx_t* test_ctx, uint16_t qid)
{
    uint64_t r_time = UINT64_MAX;

    if (test_ctx->record[qid].queued_response != NULL){  
        r_time = test_ctx->record[qid].query_arrival_time;
        if (test_ctx->record[qid].queued_response->response_length > 0) {
            r_time += test_ctx->scenario[qid].response_delay;
        }
    }
    else if (test_ctx->record[qid].queued_packet != NULL) {
        r_time = test_ctx->record[qid].queued_packet->arrival_time;
    }

    if (r_time < test_ctx->next_response_time) {
        test_ctx->next_response_time = r_time;
        test_ctx->next_response_id = qid;
    }
}

void quicdoq_reset_test_response_queue(quicdog_test_ctx_t* test_ctx)
{
    test_ctx->next_response_id = test_ctx->nb_scenarios;
    test_ctx->next_response_time = UINT64_MAX;

    for (uint16_t qid = 0; qid < test_ctx->nb_scenarios; qid++) {
        if (test_ctx->record[qid].query_received && 
            (test_ctx->record[qid].queued_response != NULL || test_ctx->record[qid].queued_packet != NULL)){
            quicdoq_set_test_response_queue(test_ctx, qid);
        }
    }
}

int quicdoq_test_server_cb(
    quicdoq_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdog_test_ctx_t* test_ctx = (quicdog_test_ctx_t*)callback_ctx;
    uint16_t qid = quicdog_test_get_query_id(query_ctx);

    switch (callback_code) {
    case quicdoq_incoming_query: /* Incoming callback query */
        if (qid > test_ctx->nb_scenarios || test_ctx->record[qid].query_received) {
            ret = -1;
        }
        else {
            test_ctx->record[qid].query_arrival_time = current_time;
            test_ctx->record[qid].query_received = 1;
            /* queue the response */
            if (!test_ctx->scenario[qid].is_success ||
                quicdog_test_get_format_response(query_ctx->query, query_ctx->query_length,
                    query_ctx->response, query_ctx->response_max_size, &query_ctx->response_length) != 0) {
                query_ctx->response_length = 0; /* This will trigger a cancellation */
            }
            test_ctx->record[qid].queued_response = query_ctx;
            quicdoq_set_test_response_queue(test_ctx, qid);
        }
        break;
    case quicdoq_query_cancelled: /* Query cancelled before response provided */
    case quicdoq_query_failed: /* Query failed for reasons other than cancelled. */
        /* remove response from queue, mark it cancelled */
        if (qid > test_ctx->nb_scenarios || !test_ctx->record[qid].query_received || test_ctx->record[qid].queued_response) {
            ret = -1;
        }
        else {
            test_ctx->record[qid].queued_response = NULL;
            test_ctx->record[qid].response_sent_time = test_ctx->simulated_time;
            test_ctx->record[qid].server_error = 1;
        }
        quicdoq_reset_test_response_queue(test_ctx);
        break;
    default: /* callback code not expected on server */
        ret = -1;
        break;
    }

    return ret;
}

int quicdoq_test_server_submit_response(quicdog_test_ctx_t* test_ctx)
{
    int ret = 0;

    /* Check whether the next query is ready */
    if (test_ctx->next_response_id >= test_ctx->nb_scenarios ||
        test_ctx->record[test_ctx->next_response_id].queued_response == NULL) {
        ret = -1;
    }
    else {
        /* submit the response */
        if (test_ctx->record[test_ctx->next_response_id].queued_response->response_length > 0) {
            ret = quicdoq_post_response(test_ctx->record[test_ctx->next_response_id].queued_response);
        }
        else {
            ret = quicdoq_cancel_response(test_ctx->qd_server, test_ctx->record[test_ctx->next_response_id].queued_response,
                QUICDOQ_ERROR_INTERNAL);
        }
        test_ctx->record[test_ctx->next_response_id].queued_response = NULL;
        test_ctx->record[test_ctx->next_response_id].response_sent_time = test_ctx->simulated_time;

        quicdoq_reset_test_response_queue(test_ctx);
    }

    return ret;
}

/* Client call back and submit function for tests
 */

int quicdoq_test_client_cb(
    quicdoq_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdog_test_ctx_t* test_ctx = (quicdog_test_ctx_t*)callback_ctx;
    uint16_t qid = quicdog_test_get_query_id(query_ctx);

    if (qid > test_ctx->nb_scenarios) {
        ret = -1;
    } if (test_ctx->record[qid].response_received) {
        ret = -1;
    }
    else {
        test_ctx->record[qid].response_received = 1;
        test_ctx->record[qid].response_arrival_time = current_time;

        switch (callback_code) {
        case quicdoq_response_complete: /* The response to the current query arrived. */
            /* tabulate completed */
            test_ctx->record[qid].is_success = 1;
            if (!test_ctx->scenario[qid].is_success) {
                test_ctx->some_query_inconsistent = 1;
            }
            break;
        case quicdoq_response_cancelled: /* The response to the current query was cancelled by the peer. */
            /* tabulate cancelled */
            test_ctx->record[qid].cancel_received = 1;
            if (test_ctx->scenario[qid].is_success) {
                test_ctx->some_query_inconsistent = 1;
            }
            break;
        case quicdoq_query_failed:  /* Query failed for reasons other than cancelled. */
            /* tabulate failed */
            test_ctx->some_query_failed = 1;
            break;
        default: /* callback code not expected on client */
            ret = -1;
            break;
        }

        /* Check whether there are still responses pending. */
        test_ctx->all_query_served = 1;
        for (uint16_t i = 0; i < test_ctx->nb_scenarios; i++) {
            if (!test_ctx->record[i].response_received) {
                test_ctx->all_query_served = 0;
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

int quicdoq_test_client_submit_query(quicdog_test_ctx_t* test_ctx)
{
    int ret = 0;
    quicdoq_query_ctx_t* query_ctx = NULL;

    /* Check whether the next query is ready */
    if (test_ctx->next_query_id >= test_ctx->nb_scenarios ||
        test_ctx->scenario[test_ctx->next_query_id].schedule_time < test_ctx->simulated_time ||
        test_ctx->record[test_ctx->next_query_id].query_sent) {
        ret = -1;
    }
    else {
        /* create a query record */
        query_ctx = quicdoq_create_query_ctx(512, 1024);
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

        (void)picoquic_sprintf(name_buf, sizeof(name_buf), &name_length, "%d.example.com", test_ctx->next_query_id);
        qbuf = quicdog_format_dns_query(qbuf, qbuf_max, name_buf, test_ctx->next_query_id, 0, 1, query_ctx->response_max_size);
        if (qbuf == NULL) {
            ret = -1;
        }
        else {
            query_ctx->query_length = (uint16_t)(qbuf - query_ctx->query);

            query_ctx->server_name = PICOQUIC_TEST_SNI;
            query_ctx->client_addr = (struct sockaddr*) & test_ctx->client_addr;
            query_ctx->server_addr = (struct sockaddr*) & test_ctx->server_addr;
            query_ctx->client_cb = quicdoq_test_client_cb;
            query_ctx->client_cb_ctx = test_ctx;

            ret = quicdoq_post_query(test_ctx->qd_client, query_ctx);
        }
    }

    /* Set the context for the next query after that */
    if (ret == 0) {
        test_ctx->next_query_id++;
        if (test_ctx->next_query_id >= test_ctx->nb_scenarios) {
            test_ctx->next_query_time = UINT64_MAX;
        }
        else {
            test_ctx->next_query_time = test_ctx->scenario[test_ctx->next_query_id].schedule_time;
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

void quicdoq_test_ctx_delete(quicdog_test_ctx_t* test_ctx)
{
    if (test_ctx->qd_client != NULL) {
        quicdoq_delete(test_ctx->qd_client);
        test_ctx->qd_client = NULL;
    }

    if (test_ctx->udp_ctx != NULL) {
        quicdoq_delete_udp_ctx(test_ctx->udp_ctx);
        test_ctx->udp_ctx = NULL;
    }

    if (test_ctx->qd_server != NULL) {
        quicdoq_delete(test_ctx->qd_server);
        test_ctx->qd_server = NULL;
    }

    if (test_ctx->client_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->client_link);
        test_ctx->client_link = NULL;
    }

    if (test_ctx->server_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->server_link);
        test_ctx->server_link = NULL;
    }

    if (test_ctx->udp_link_in != NULL) {
        picoquictest_sim_link_delete(test_ctx->udp_link_in);
        test_ctx->udp_link_in = NULL;
    }

    if (test_ctx->udp_link_out != NULL) {
        picoquictest_sim_link_delete(test_ctx->udp_link_out);
        test_ctx->udp_link_out = NULL;
    }

    free(test_ctx);
}

quicdog_test_ctx_t* quicdoq_test_ctx_create(quicdoq_test_scenario_entry_t const * scenario, size_t size_of_scenario, int test_udp)
{
    quicdog_test_ctx_t* test_ctx = (quicdog_test_ctx_t*)malloc(sizeof(quicdog_test_ctx_t));

    if (test_ctx != NULL) {
        int ret = 0;
        memset(test_ctx, 0, sizeof(quicdog_test_ctx_t));
        /* Locate the default cert, key and root in the Picoquic solution*/
        ret = picoquic_get_input_path(test_ctx->test_server_cert_file, sizeof(test_ctx->test_server_cert_file),
            quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_ctx->test_server_key_file, sizeof(test_ctx->test_server_key_file),
                quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            ret = picoquic_get_input_path(test_ctx->test_server_cert_store_file, sizeof(test_ctx->test_server_cert_store_file),
                quicdoq_test_picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
        }

        /* Set test addresses for client and server */
        if (ret == 0) {
            ret = picoquic_store_text_addr(&test_ctx->server_addr, "1::1", 443);
        }

        if (ret == 0) {
            ret = picoquic_store_text_addr(&test_ctx->client_addr, "2::2", 12345);
        }

        if (ret == 0) {
            ret = picoquic_store_text_addr(&test_ctx->udp_addr, "3::3", 763);
        }

        /* create the client and server contexts */
        test_ctx->qd_server = quicdoq_create(NULL,
            test_ctx->test_server_cert_file, test_ctx->test_server_key_file, NULL, NULL, NULL,
            quicdoq_test_server_cb, (void*)test_ctx,
            &test_ctx->simulated_time);
        test_ctx->qd_client = quicdoq_create(NULL,
            NULL, NULL, test_ctx->test_server_cert_store_file, NULL, NULL,
            quicdoq_test_client_cb, (void*)test_ctx,
            &test_ctx->simulated_time);

        if (test_udp && test_ctx->qd_server != NULL) {
            test_ctx->udp_ctx = quicdoq_create_udp_ctx(test_ctx->qd_server, (struct sockaddr*) & test_ctx->udp_addr);

            if (test_ctx->udp_ctx != NULL) {
                test_ctx->qd_server->app_cb_fn = quicdoq_udp_callback;
                test_ctx->qd_server->app_cb_ctx = (void *)test_ctx->udp_ctx;
            }
        }

        /* Create the simulation links */
        test_ctx->server_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        test_ctx->client_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        if (test_udp) {
            test_ctx->udp_link_in = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
            test_ctx->udp_link_out = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
        }

        /* Insert the scenarios */
        test_ctx->nb_scenarios = (uint16_t)(size_of_scenario / sizeof(quicdoq_test_scenario_entry_t));
        test_ctx->scenario = scenario;
        test_ctx->record = (quicdoq_test_scenario_record_t*)malloc(test_ctx->nb_scenarios * sizeof(quicdoq_test_scenario_record_t));
        if (test_ctx->record != NULL) {
            memset(test_ctx->record, 0, test_ctx->nb_scenarios * sizeof(quicdoq_test_scenario_record_t));
        }
        test_ctx->next_query_time = test_ctx->scenario[0].schedule_time;
        test_ctx->next_response_time = UINT64_MAX;
        if (ret != 0 || test_ctx->qd_client == NULL || test_ctx->qd_server == NULL ||
            test_ctx->server_link == NULL || test_ctx->client_link == NULL || test_ctx->record == NULL ||
            (test_udp && (test_ctx->udp_ctx == NULL || test_ctx->udp_link_in == NULL || test_ctx->udp_link_out == NULL))) {
            quicdoq_test_ctx_delete(test_ctx);
                test_ctx = NULL;
        }
    }
    return test_ctx;
}

int quicdoq_test_sim_packet_input(quicdog_test_ctx_t* test_ctx, picoquic_quic_t* quic, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, test_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;
        ret = picoquic_incoming_packet(quic, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*) & packet->addr_from,
            (struct sockaddr*) & packet->addr_to, 0, 0,
            test_ctx->simulated_time);
        free(packet);
    }

    return ret;
}

int quicdoq_test_sim_packet_prepare(quicdog_test_ctx_t* test_ctx, quicdoq_ctx_t* quicdoq_ctx, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(quicdoq_ctx->quic, test_ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            ret = -1;
        }
        else if (packet->addr_from.ss_family == 0) {
            picoquic_store_addr(&packet->addr_from, (quicdoq_ctx == test_ctx->qd_client) ?
                (struct sockaddr*) & test_ctx->client_addr : (struct sockaddr*) & test_ctx->server_addr);
        }
    }

    /* TODO: check that dest and srce address are what is expected */

    if (ret == 0 && packet->length > 0) {
        *is_active = 1;
        picoquictest_sim_link_submit(link, packet, test_ctx->simulated_time);
    } else {
        free(packet);
    }

    return ret;
}

/* Simulated departure of a packet towards the remote UDP server.
 */

int quicdoq_test_udp_packet_prepare(quicdog_test_ctx_t* test_ctx, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    int if_index = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        quicdoq_udp_prepare_next_packet(test_ctx->udp_ctx, test_ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from,&if_index);
    }

    if (ret == 0 && packet->length > 0) {
        *is_active = 1;
        picoquictest_sim_link_submit(link, packet, test_ctx->simulated_time);
    }
    else {
        free(packet);
    }

    return ret;
}

/* Simulated arrival of a packet from remote UDP server.
 */

int quicdoq_test_sim_udp_input(quicdog_test_ctx_t* test_ctx, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, test_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;
        quicdoq_udp_incoming_packet(test_ctx->udp_ctx, packet->bytes, (uint32_t)packet->length, 
            (struct sockaddr*)&packet->addr_to, 0, test_ctx->simulated_time);
        free(packet);
    }

    return ret;
}

/* Simulated arrival of a packet at the remote UDP server.
 * Find the test scenario line ID by parsing the first name part as a number.
 * If that query is meant to succeed, format a response and queue it for the specified delay.
 * If it is meant to fail, do not format a response at all. The query should time out.
 */

int quicdoq_test_sim_udp_output(quicdog_test_ctx_t* test_ctx, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, test_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        /* Obtain the query ID from the name. */
        uint16_t qid = 0;
        uint8_t l = packet->bytes[12];

        for (uint8_t x = 0; x < l; x++) {
            int c = packet->bytes[13 + x];
            if (c < '0' || c > '9') {
                ret = -1;
                break;
            }
            else {
                qid = (uint16_t)(10 * qid + c - '0');
            }
        }

        if (ret == 0) {
            picoquictest_sim_packet_t* queued = picoquictest_sim_link_create_packet();

            if (qid > test_ctx->nb_scenarios || queued == NULL) {
                ret = -1;
            }
            else {
                if (!test_ctx->record[qid].query_received) {
                    test_ctx->record[qid].query_arrival_time = test_ctx->simulated_time + test_ctx->scenario[qid].response_delay;
                    test_ctx->record[qid].query_received = 1;
                }
                *is_active = 1;

                /* queue the response */
                if (test_ctx->scenario[qid].is_success) {
                    if (quicdog_test_get_format_response(packet->bytes, packet->length,
                        queued->bytes, PICOQUIC_MAX_PACKET_SIZE, &queued->length) == 0) {
                        test_ctx->record[qid].queued_packet = queued;
                        quicdoq_set_test_response_queue(test_ctx, qid);
                    }
                    else {
                        DBG_PRINTF("Cannot format response to query #%d", qid);
                        ret = -1;
                    }
                }
                else {
                    /* Simulating a non response. No packet sent if the query is meant to fail. */
                    DBG_PRINTF("Simulating non response response to query #%d", qid);
                    free(queued);
                    queued = NULL;
                }
            }

            if (ret != 0 && queued != NULL) {
                free(queued);
            }
        }

        free(packet);
    }

    return ret;
}

/* quicdoq_test_server_sim_udp_response.
 * simulate the responses from a remote udp server.
 * The server manages a queue of responses, ordered by departure times.
 * The next response to send is at location 'test_ctx->next_response_id',
 * and there is always a packet queued for that response, unless we
 * want to simulate a non responding server that drops responses.
 * When there is a packet, post it to the specified link.
 */

int quicdoq_test_server_sim_udp_response(quicdog_test_ctx_t* test_ctx, picoquictest_sim_link_t* link, int* is_active)
{
    int ret = 0;

    /* Check whether the next query is ready */
    if (test_ctx->next_response_id >= test_ctx->nb_scenarios ||
        test_ctx->record[test_ctx->next_response_id].queued_packet == NULL) {
        ret = -1;
    }
    else {
        /* submit the response */
        picoquictest_sim_packet_t* packet = test_ctx->record[test_ctx->next_response_id].queued_packet;
        if (packet->length > 0) {
            *is_active = 1;
            picoquic_store_addr(&packet->addr_from, (struct sockaddr*) & test_ctx->udp_ctx->udp_addr);
            picoquic_store_addr(&packet->addr_to, (struct sockaddr*) & test_ctx->server_addr);
            picoquictest_sim_link_submit(link, packet, test_ctx->simulated_time);
        }
        else {
            /* Just drop the response */
            free(packet);
        }
        test_ctx->record[test_ctx->next_response_id].queued_packet = NULL;
        test_ctx->record[test_ctx->next_response_id].response_sent_time = test_ctx->simulated_time;
    }

    quicdoq_reset_test_response_queue(test_ctx);

    return ret;
}

int quicdoq_test_sim_step(quicdog_test_ctx_t* test_ctx, int * is_active)
{
    int ret = 0;
    uint64_t next_time = UINT64_MAX;
    uint64_t try_time;
    int next_step = -1;

    *is_active = 0;

    if ((try_time = picoquic_get_next_wake_time(test_ctx->qd_client->quic, test_ctx->simulated_time)) < next_time) {
        next_time = try_time;
        next_step = 0;
    }

    if ((try_time = picoquic_get_next_wake_time(test_ctx->qd_server->quic, test_ctx->simulated_time)) < next_time) {
        next_time = try_time;
        next_step = 1;
    }

    if (test_ctx->client_link->first_packet != NULL &&
        test_ctx->client_link->first_packet->arrival_time < next_time) {
        next_time = test_ctx->client_link->first_packet->arrival_time;
        next_step = 2;
    }

    if (test_ctx->server_link->first_packet != NULL &&
        test_ctx->server_link->first_packet->arrival_time < next_time) {
        next_time = test_ctx->server_link->first_packet->arrival_time;
        next_step = 3;
    }

    if (test_ctx->next_query_time < next_time) {
        next_time = test_ctx->next_query_time;
        next_step = 4;
    }

    if (test_ctx->next_response_time < next_time) {
        next_time = test_ctx->next_response_time;
        next_step = 5;
    }

    if (test_ctx->udp_ctx != NULL) {
        if (test_ctx->udp_ctx->next_wake_time < next_time) {
            next_time = test_ctx->udp_ctx->next_wake_time;
            next_step = 6;
        }

        if (test_ctx->udp_link_in->first_packet != NULL &&
            test_ctx->udp_link_in->first_packet->arrival_time < next_time) {
            next_time = test_ctx->udp_link_in->first_packet->arrival_time;
            next_step = 7;
        }

        if (test_ctx->udp_link_out->first_packet != NULL &&
            test_ctx->udp_link_out->first_packet->arrival_time < next_time) {
            next_time = test_ctx->udp_link_out->first_packet->arrival_time;
            next_step = 8;
        }
    }

    /* Update the virtual time */
    if (next_time > test_ctx->simulated_time) {
        test_ctx->simulated_time = next_time;
    }

    /* Execute the most urgent action. */
    switch (next_step) {
    case 0:
        ret = quicdoq_test_sim_packet_prepare(test_ctx, test_ctx->qd_client, test_ctx->server_link, is_active);
        break;
    case 1:
        ret = quicdoq_test_sim_packet_prepare(test_ctx, test_ctx->qd_server, test_ctx->client_link, is_active);
        break;
    case 2:
        ret = quicdoq_test_sim_packet_input(test_ctx, test_ctx->qd_client->quic, test_ctx->client_link, is_active);
        break;
    case 3:
        ret = quicdoq_test_sim_packet_input(test_ctx, test_ctx->qd_server->quic, test_ctx->server_link, is_active);
        break;
    case 4:
        ret = quicdoq_test_client_submit_query(test_ctx);
        break;
    case 5:
        if (test_ctx->udp_ctx == NULL) {
            ret = quicdoq_test_server_submit_response(test_ctx);
        }
        else {
            /* if testing UDP, simulate remote UDP server */
            ret = quicdoq_test_server_sim_udp_response(test_ctx, test_ctx->udp_link_in, is_active);
        }
        break;
    case 6:
        /* Prepare UDP output */
        ret = quicdoq_test_udp_packet_prepare(test_ctx, test_ctx->udp_link_out, is_active);
        break;
    case 7:
        /* Prepare arrival on udp_link_in */
        ret = quicdoq_test_sim_udp_input(test_ctx, test_ctx->udp_link_in, is_active);
        break;
    case 8:
        /* Prepare arrival on udp_link_out */
        ret = quicdoq_test_sim_udp_output(test_ctx, test_ctx->udp_link_out, is_active);
        break;
    default:
        /* Nothing to do, which is unlikely since the server is always up. */
        ret = -1;
        break;
    }

    return ret;
}

int quicdoq_test_sim_run(quicdog_test_ctx_t* test_ctx, uint64_t time_limit)
{
    int ret = 0;
    int is_active = 0;
    int inactive_count = 0;

    while (ret == 0 && !test_ctx->all_query_served && inactive_count < 1204 && test_ctx->simulated_time < time_limit) {
        ret = quicdoq_test_sim_step(test_ctx, &is_active);

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

int quicdoq_test_scenario(quicdoq_test_scenario_entry_t const* scenario, size_t size_of_scenario, int test_udp, uint64_t time_limit)
{
    quicdog_test_ctx_t* test_ctx = quicdoq_test_ctx_create(scenario, size_of_scenario, test_udp);
    int ret = 0;

    if (test_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = quicdoq_test_sim_run(test_ctx, time_limit);

        if (ret != 0 || !test_ctx->all_query_served || test_ctx->some_query_failed || test_ctx->some_query_inconsistent) {
            DBG_PRINTF("Fail after %llu, all_served=%d (inconsistent=%d, failed=%d), ret=%d",
                (unsigned long long)test_ctx->simulated_time, test_ctx->all_query_served,
                test_ctx->some_query_inconsistent, test_ctx->some_query_failed, ret);
            ret = -1;
        }
        quicdoq_test_ctx_delete(test_ctx);
    }

    return ret;
}

int quicdoq_basic_test()
{
    return quicdoq_test_scenario(basic_scenario, sizeof(basic_scenario), 0, 3000000);
}

int quicdoq_basic_udp_test()
{
    return quicdoq_test_scenario(basic_scenario, sizeof(basic_scenario), 1, 3000000);
}

/* Basic scenario: just one query, immediate positive response */
static quicdoq_test_scenario_entry_t const multi_queries_scenario[] = {
    { 0, 0, 1 },
    { 0, 0, 1 }
};

int quicdoq_multi_queries_test()
{
    return quicdoq_test_scenario(multi_queries_scenario, sizeof(multi_queries_scenario), 0, 3000000);
}

int quicdoq_multi_udp_test()
{
    return quicdoq_test_scenario(multi_queries_scenario, sizeof(multi_queries_scenario), 1, 3000000);
}

/* One loss scenario: one query, immediate negative response */
static quicdoq_test_scenario_entry_t const one_loss_scenario[] = {
    { 0, 0, 0 }
};

int quicdoq_one_loss_test()
{
    return quicdoq_test_scenario(one_loss_scenario, sizeof(one_loss_scenario), 0, 3000000);
}

int quicdoq_one_loss_udp_test()
{
    return quicdoq_test_scenario(one_loss_scenario, sizeof(one_loss_scenario), 1, 10000000);
}