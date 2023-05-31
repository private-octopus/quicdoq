/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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


#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include "picoquic.h"
#include "picosocks.h"
#include "picoquic_utils.h"
#include "quicdoq.h"
#include "autoqlog.h"

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "quicdoq.h"
#include "picosocks.h"
#include "autoqlog.h"

#if 0
#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#endif

#include "picoquic_binlog.h"
#include "picoquic_logger.h"

typedef struct st_quicdoq_demo_client_ctx_t {
    quicdoq_ctx_t* qd_client;
    char test_server_cert_store_file[512];
    uint16_t nb_client_queries;
    quicdoq_query_ctx_t** query_ctx;
    int * is_query_complete;
    uint64_t start_time;
    uint64_t next_query_time;
    uint16_t next_query_id;
    int all_queries_served;
} quicdoq_demo_client_ctx_t;

void usage();
uint32_t parse_target_version(char const* v_arg);
int quicdoq_demo_server(
    const char* alpn, const char* server_cert_file, const char* server_key_file, const char* log_file,
    const char* binlog_dir, char const* qlog_dir, const char* backend_dns_server, const char* solution_dir,
    int use_long_log, int server_port, int dest_if, int mtu_max, int do_retry,
    uint64_t* reset_seed, char const* cc_algo_id);
int quicdoq_client(const char* server_name, int server_port, int dest_if,
    const char* sni, const char* alpn, const char* root_crt,
    int mtu_max, const char* log_file, char const* binlog_dir, char const* qlog_dir, int use_long_log,
    int client_cnx_id_length, char const* cc_algo_id,
    int nb_client_queries, char const** client_query_text);
int quicdoq_demo_client_init_context(quicdoq_ctx_t* qd_client, quicdoq_demo_client_ctx_t * client_ctx, int nb_client_queries, char const** client_query_text,
    char const* server_name, struct sockaddr* server_addr, struct sockaddr* client_addr, uint64_t current_time);
void quicdoq_demo_client_reset_context(quicdoq_ctx_t* qd_client, quicdoq_demo_client_ctx_t * client_ctx);
int quicdoq_demo_client_cb(quicdoq_query_return_enum callback_code, void* callback_ctx, quicdoq_query_ctx_t* query_ctx, uint64_t current_time);

int main(int argc, char** argv)
{
    int ret = 0;
    const char* server_name = NULL;
    const char* server_cert_file = NULL;
    const char* server_key_file = NULL;
    const char* log_file = NULL;
    const char* binlog_dir = NULL;
    const char* qlog_dir = NULL;
    const char* sni = NULL;
    const char* alpn = NULL;
    const char* root_trust_file = NULL;
    const char* backend_dns_server = NULL;
    const char* solution_dir = NULL;
    const char* cc_algo_id = NULL;

    int use_long_log = 0;
    int server_port = QUICDOQ_PORT;
    int dest_if = -1;
    int mtu_max = 0;
    int do_retry = 0;
    uint64_t* reset_seed = NULL;
    uint64_t reset_seed_x[2];
    uint32_t proposed_version = 0;
    int client_cnx_id_length = 8;
    const char** client_query_text = NULL;
    const char* default_query = "example.com:A";
    const char* default_query_query_list[2]; 
    int nb_client_queries = 0;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:K:E:l:b:q:Lp:e:m:n:a:rs:t:v:I:G:S:d:h")) != -1) {
        switch (opt) {
        case 'c':
            server_cert_file = optarg;
            break;
        case 'k':
            server_key_file = optarg;
            break;
        case 'l':
            log_file = optarg;
            break;
        case 'b':
            binlog_dir = optarg;
            break;
        case 'q':
            qlog_dir = optarg;
            break;
        case 'L':
            use_long_log = 1;
            break;
        case 'p':
            if ((server_port = atoi(optarg)) <= 0) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                usage();
            }
            break;
        case 'e':
            dest_if = atoi(optarg);
            break;
        case 'm':
            mtu_max = atoi(optarg);
            if (mtu_max <= 0 || mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
                fprintf(stderr, "Invalid max mtu: %s\n", optarg);
                usage();
            }
            break;
        case 'n':
            sni = optarg;
            break;
        case 'a':
            alpn = optarg;
            break;
        case 'r':
            do_retry = 1;
            break;
        case 's':
            if (optind + 1 > argc) {
                fprintf(stderr, "option requires more arguments -- s\n");
                usage();
            }
            reset_seed = reset_seed_x; /* replacing the original alloca, which is not supported in Windows or BSD */
            reset_seed[1] = strtoul(optarg, NULL, 0);
            reset_seed[0] = strtoul(argv[optind++], NULL, 0);
            break;
        case 't':
            root_trust_file = optarg;
            break;
        case 'v':
            if ((proposed_version = parse_target_version(optarg)) <= 0) {
                fprintf(stderr, "Invalid version: %s\n", optarg);
                usage();
            }
            break;
        case 'I':
            client_cnx_id_length = atoi(optarg);
            if (client_cnx_id_length < 0 || client_cnx_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
                fprintf(stderr, "Invalid connection id length: %s\n", optarg);
                usage();
            }
            break;
        case 'G':
            cc_algo_id = optarg;
            break;
        case 'S':
            solution_dir = optarg;
            break;
        case 'd':
            backend_dns_server = optarg;
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            break;
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        /* Start client using specified options */
        server_name = argv[optind++];

        if (optind < argc) {
            if ((server_port = atoi(argv[optind++])) <= 0) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                usage();
            }
        }

        if (optind < argc) {
            client_query_text = (const char **)(argv + optind);
            nb_client_queries = argc - optind;
        }
        else {
            default_query_query_list[0] = default_query;
            default_query_query_list[1] = NULL;
            client_query_text = default_query_query_list;
            nb_client_queries = 1;
        }

        ret = quicdoq_client(server_name, server_port, dest_if, sni, alpn, root_trust_file,
            mtu_max, log_file, binlog_dir, qlog_dir, use_long_log, client_cnx_id_length, cc_algo_id,
            nb_client_queries, client_query_text);
    }
    else {
        /* start server using specified options */
        ret = quicdoq_demo_server(alpn, server_cert_file, server_key_file, 
            log_file, binlog_dir, qlog_dir, backend_dns_server, solution_dir, use_long_log, server_port, dest_if, 
            mtu_max, do_retry, reset_seed, cc_algo_id);
    }

    return ret;
}

void usage()
{
    fprintf(stderr, "Quicdoq demo client and server\n");
    fprintf(stderr, "Client: quicdoq_app <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "Server: quicdoq_app <options> -p port -d dns-server\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c file               cert file (default: %s)\n", SERVER_CERT_FILE);
    fprintf(stderr, "  -h                    This help message\n");
    fprintf(stderr, "  -k file               key file (default: %s)\n", SERVER_KEY_FILE);
    fprintf(stderr, "  -l file               Log file, Log to stdout if file = \"n\". No logging if absent.\n");
    fprintf(stderr, "  -b bin_dir            Binary logging to this directory. No binary logging if absent.\n");
    fprintf(stderr, "  -q qlog_dir           Qlog logging to this directory. No qlog logging if absent,\n");
    fprintf(stderr, "                        but qlogs could be extracted from binary logs using picolog\n");
    fprintf(stderr, "                        if binary logs are available.\n");
    fprintf(stderr, "                        Production of qlogs on servers affects performance.\n");
    fprintf(stderr, "  -L                    Log all packets. If absent, log stops after 100 packets.\n");
    fprintf(stderr, "  -p port               server port (default: %d)\n", QUICDOQ_PORT);
    fprintf(stderr, "  -e if                 Send on interface (default: -1)\n");
    fprintf(stderr, "                           -1: receiving interface\n");
    fprintf(stderr, "                            0: routing lookup\n");
    fprintf(stderr, "                            n: ifindex\n");
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -n sni                sni (default: server name)\n");
    fprintf(stderr, "  -a alpn               alpn (default: doq)\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -t file               root trust file\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff000012\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");
    fprintf(stderr, "  -I length             Length of CNX_ID used by the client, default=8\n");
    fprintf(stderr, "  -G cc_algorithm       Use the specified congestion control algorithm:\n");
    fprintf(stderr, "                        reno, cubic, bbr or fast. Defaults to bbr.\n");
    fprintf(stderr, "  -S solution_dir       Set the path to the solution folder, to find the default files\n");
    fprintf(stderr, "  -d dns_server         name or address of backend DNS server (default 1.1.1.1).\n");

    fprintf(stderr, "\nIn client mode, the scenario provides the list of names to be resolved\n");
    fprintf(stderr, "and the record type, e.g.:\n");
    fprintf(stderr, "   www.example:A www.example.example:AAAA example.net:NS\n");
    fprintf(stderr, "If no scenario is specified, the client looks for example.com:A.\n");
    fprintf(stderr, "\nIn server mode, the queries are sent over UDP to the backend DNS server\n");
    fprintf(stderr, "specified in the -d argument.\n");

    exit(1);
}

/* TODO: replace by generic call to parse hex strings  */
uint32_t parse_target_version(char const* v_arg)
{
    /* Expect the version to be encoded in base 16 */
    uint32_t v = 0;
    char const* x = v_arg;

    while (*x != 0) {
        int c = *x;

        if (c >= '0' && c <= '9') {
            c -= '0';
        }
        else if (c >= 'a' && c <= 'f') {
            c -= 'a';
            c += 10;
        }
        else if (c >= 'A' && c <= 'F') {
            c -= 'A';
            c += 10;
        }
        else {
            v = 0;
            break;
        }
        v *= 16;
        v += c;
        x++;
    }

    return v;
}

/* 
 * Simple DoQ server.
 *
 * The server assumes that the DNS queries will be served by a backend UDP server.
 * By default, the address of that server is set to "1.1.1.1" (the Cloudflare service).
 *
 * 
 */

int quicdoq_demo_server(
    const char* alpn, const char* server_cert_file, const char* server_key_file, const char* log_file,
    const char* binlog_dir, char const* qlog_dir, const char* backend_dns_server, const char* solution_dir,
    int use_long_log, int server_port, int dest_if, int mtu_max, int do_retry,
    uint64_t* reset_seed, char const * cc_algo_id)
{
    int ret = 0;
    char default_server_cert_file[512];
    char default_server_key_file[512];
    quicdoq_ctx_t * qd_server = NULL;
    quicdoq_udp_ctx_t * udp_ctx = NULL;
    struct sockaddr_storage udp_addr;
    picoquic_server_sockets_t server_sockets;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    FILE* F_log = NULL;

#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(reset_seed);
#endif

    if (solution_dir == NULL) {
#ifdef _WINDOWS
#ifdef _WINDOWS64
        solution_dir = "..\\..\\..\\picoquic";
#else
        solution_dir = "..\\..\\picoquic";
#endif
#else
        solution_dir = "../picoquic";
#endif
    }


    if (backend_dns_server == NULL) {
        backend_dns_server = "1.1.1.1";
    }

    printf("Starting the quicdoq server on port %d, back end UDP server %s\n", server_port, backend_dns_server);

    /* Verify that the cert and key are defined. */
    if (server_cert_file == NULL &&
        (ret = picoquic_get_input_path(default_server_cert_file, sizeof(default_server_cert_file),
            solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT)) == 0){
        server_cert_file = default_server_cert_file;
    }

    if (server_key_file == NULL && ret == 0 &&
        (ret = picoquic_get_input_path(default_server_key_file, sizeof(default_server_key_file),
            solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY)) == 0){
        server_key_file = default_server_key_file;
    }

    /* Verify that the UDP server address is available */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(backend_dns_server, 53, &udp_addr, &is_name);
        if (ret != 0) {
            printf("Cannot parse the backend dns server name: %s\n", backend_dns_server);
        }
    }

    /* Create the server context */
    if (ret == 0) {
        /* Create a Quic Doq context for the server */
        qd_server = quicdoq_create(alpn, server_cert_file, server_key_file, NULL, NULL, NULL,
            quicdoq_udp_callback, NULL, NULL);
        if (qd_server == NULL) {
            ret = -1;
        }
        else {
            udp_ctx = quicdoq_create_udp_ctx(qd_server, (struct sockaddr*) & udp_addr);
            if (udp_ctx == NULL) {
                ret = -1;
            }
            else {
                quicdoq_set_callback(qd_server, quicdoq_udp_callback, udp_ctx);
            }
        }
    }

    if (ret == 0) {
        /* set the extra server parameters */
        picoquic_quic_t* quic = quicdoq_get_quic_ctx(qd_server);

        if (do_retry != 0) {
            picoquic_set_cookie_mode(quic, 1);
        }

        picoquic_set_mtu_max(quic, mtu_max);

        picoquic_set_default_congestion_algorithm_by_name(quic, cc_algo_id);

        if (log_file != NULL) {
            picoquic_set_textlog(quic, log_file);
        }

        if (binlog_dir != NULL) {
            picoquic_set_binlog(quic, binlog_dir);
        }

        if (qlog_dir != NULL) {
            picoquic_set_qlog(quic, qlog_dir);
        }

        picoquic_set_log_level(quic, use_long_log);

        picoquic_set_key_log_file_from_env(quic);
    }

    if (ret == 0) {
        /* start the local sockets */
        ret = picoquic_open_server_sockets(&server_sockets, server_port);
    }


    while (ret == 0) {
        /* do the server loop */
        unsigned char received_ecn;
        int bytes_recv;
        uint64_t delta_t = 0;
        uint64_t current_time = picoquic_current_time();
        uint64_t next_time = picoquic_get_next_wake_time(quicdoq_get_quic_ctx(qd_server), current_time);

        if (quicdoq_next_udp_time(udp_ctx) < next_time) {
            next_time = quicdoq_next_udp_time(udp_ctx);
        }

        if (next_time > current_time) {
            delta_t = next_time - current_time;

            if (delta_t > INT64_MAX) {
                delta_t = INT64_MAX;
            }
        }

        if_index_to = 0;
        
        bytes_recv = picoquic_select(server_sockets.s_socket, PICOQUIC_NB_SERVER_SOCKETS,
                &addr_from,
                &addr_to, &if_index_to, &received_ecn,
                buffer, sizeof(buffer),
                (int64_t)delta_t, &current_time);

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time;

            size_t send_length = 0;

            if (bytes_recv > 0) {
                if (picoquic_compare_addr((struct sockaddr*) & addr_from, (struct sockaddr*) & udp_addr) == 0) {
                    /* This is a packet from the UDP server. Send it there */
                    quicdoq_udp_incoming_packet(udp_ctx, buffer, (uint32_t)bytes_recv, (struct sockaddr*) & addr_to, if_index_to, current_time);
                }
                else {
                    /* Submit the packet to the Quic server */
                    (void)picoquic_incoming_packet(quicdoq_get_quic_ctx(qd_server), buffer,
                        (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                        (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                        current_time);
                }
            }

            do {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                picoquic_cnx_t *last_cnx = NULL;
                picoquic_connection_id_t log_cid = { 0 };
                int if_index = dest_if;

                loop_time = picoquic_current_time();

                send_length = 0;

                if (quicdoq_next_udp_time(udp_ctx) <= current_time) {
                    /* check whether there is something to send */
                    quicdoq_udp_prepare_next_packet(udp_ctx, loop_time,
                        send_buffer, sizeof(send_buffer), &send_length,
                        &peer_addr, &local_addr, &if_index);
                }

                if (send_length == 0 && picoquic_get_next_wake_time(quicdoq_get_quic_ctx(qd_server), current_time) <= current_time) {
                    ret = picoquic_prepare_next_packet(quicdoq_get_quic_ctx(qd_server), loop_time,
                        send_buffer, sizeof(send_buffer), &send_length,
                        &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);
                }

                if (ret == 0 && send_length > 0) {
                    int sock_err = 0;
                    int sock_ret = picoquic_send_through_server_sockets(&server_sockets,
                        (struct sockaddr*) & peer_addr,(struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);
                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quicdoq_get_quic_ctx(qd_server), &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);

                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                                    sock_err);
                            }
                        }
                    }
                }

            } while (ret == 0 && send_length > 0);
        }
    }

    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    picoquic_close_server_sockets(&server_sockets);

    if (udp_ctx != NULL) {
        quicdoq_delete_udp_ctx(udp_ctx);
    }

    if (qd_server != NULL) {
        quicdoq_delete(qd_server);
    }

    if (F_log != NULL) {
        (void) picoquic_file_close(F_log);
    }

    return ret;
}

#define QUICDOQ_DEMO_CLIENT_MAX_RECEIVE_BATCH 16

/* Quic Client */
int quicdoq_client(const char* server_name, int server_port, int dest_if,
    const char* sni, const char* alpn, const char* root_crt,
    int mtu_max, const char* log_file, char const* binlog_dir, char const* qlog_dir, int use_long_log,
    int client_cnx_id_length, char const* cc_algo_id,
    int nb_client_queries, char const** client_query_text)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    quicdoq_ctx_t* qd_client = NULL;
    picoquic_quic_t* qclient = NULL;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage packet_from;
    struct sockaddr_storage packet_to;
    int if_index_to;
    int is_name;
    int client_receive_loop = 0;
    uint8_t recv_buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    int bytes_sent;
    uint64_t current_time = 0;
    uint64_t time_out = 0;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;
    unsigned char received_ecn;
    FILE* F_log = NULL;
    quicdoq_demo_client_ctx_t client_ctx;
    char const* ticket_file = "quicdoq_client_tickets.bin";
    char const* token_file = "quicdoq_client_tokens.bin";

#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(dest_if);
#endif

    current_time = picoquic_current_time();
    time_out = current_time + 60000000;
    memset(&client_ctx, 0, sizeof(quicdoq_demo_client_ctx_t));
    memset(&client_address, 0, sizeof(struct sockaddr_storage));

    ret = picoquic_get_server_address(server_name, server_port, &server_address, &is_name);
    if (sni == NULL && is_name != 0) {
        sni = server_name;
    }

    /* Open a UDP socket */

    if (ret == 0) {
        fd = picoquic_open_client_socket(server_address.ss_family);
        if (fd == INVALID_SOCKET) {
            ret = -1;
        }
    }

    /* Create QUIC context */

    if (ret == 0) {
        /* TODO: token and ticket files! */
        qd_client = quicdoq_create(alpn, NULL, NULL, root_crt, ticket_file, token_file, quicdoq_demo_client_cb, (void*)&client_ctx, NULL);

        if (qd_client == NULL) {
            ret = -1;
        }
        else {
            qclient = quicdoq_get_quic_ctx(qd_client);

            (void)picoquic_set_default_connection_id_length(qclient, (uint8_t)client_cnx_id_length);

            picoquic_set_mtu_max(qclient, mtu_max);

            picoquic_set_default_congestion_algorithm_by_name(qclient, cc_algo_id);

            if (log_file != NULL) {
                picoquic_set_textlog(qclient, log_file);
            }

            if (binlog_dir != NULL) {
                picoquic_set_binlog(qclient, binlog_dir);
            }

            if (qlog_dir != NULL) {
                picoquic_set_qlog(qclient, qlog_dir);
            }

            picoquic_set_log_level(qclient, use_long_log);

            picoquic_set_key_log_file_from_env(qclient);
        }
    }

    /* Init the client context */
    if (ret == 0) {
        ret = quicdoq_demo_client_init_context(qd_client, &client_ctx, nb_client_queries, client_query_text,
            sni, (struct sockaddr*) & server_address, (struct sockaddr*) & client_address, current_time);

    }

    /* Loop: wait for packets, send queries, until all queries served */
    while (ret == 0 && !(client_ctx.all_queries_served && quicdoq_is_closed(qd_client))) {
        bytes_recv = picoquic_select(&fd, 1, &packet_from,
            &packet_to, &if_index_to, &received_ecn,
            recv_buffer, sizeof(recv_buffer), delta_t, &current_time);

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            if (bytes_recv > 0) {
                if (client_address.ss_family == 0) {
                    picoquic_store_addr(&client_address, (struct sockaddr*) & packet_to);
                }

                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, recv_buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & packet_from,
                    (struct sockaddr*) & packet_to, if_index_to, received_ecn,
                    current_time);
                client_receive_loop++;
                delta_t = 0;
            }

            /* In normal circumstances, the code waits until all packets in the receive
             * queue have been processed before sending new packets. However, if the server
             * is sending lots and lots of data this can lead to the client not getting
             * the occasion to send acknowledgements. The server will start retransmissions,
             * and may eventually drop the connection for lack of acks. So we limit
             * the number of packets that can be received before sending responses. */

            if (bytes_recv == 0 || (ret == 0 && client_receive_loop > QUICDOQ_DEMO_CLIENT_MAX_RECEIVE_BATCH)) {
                int x_if_index_to;
                client_receive_loop = 0;

                ret = picoquic_prepare_next_packet(qclient, current_time,
                    send_buffer, PICOQUIC_MAX_PACKET_SIZE, &send_length,
                    &packet_to, &packet_from, &x_if_index_to, NULL, NULL);

                if (ret == 0 && send_length > 0) {
                    bytes_sent = sendto(fd, (const char*)send_buffer, (int)send_length, 0,
                        (struct sockaddr*) & packet_to, picoquic_addr_length((struct sockaddr*) & packet_to));

                    if (bytes_sent <= 0)
                    {
                        fprintf(stdout, "Cannot send packet to server, returns %d\n", bytes_sent);

                        if (F_log != stdout && F_log != stderr && F_log != NULL)
                        {
                            fprintf(F_log, "Cannot send packet to server, returns %d\n", bytes_sent);
                        }
                    }
                }

                if (current_time > time_out) {
                    printf("Giving up after 60 seconds.\n");
                    break;
                }
                else {
                    delay_max = time_out - current_time;
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);
            }
        }
    }

    if (ret == 0) {

    }

    if (qclient != NULL) {
        if (picoquic_save_session_tickets(qclient, ticket_file) != 0) {
            printf("Could not save tickets in <%s>\n", ticket_file);
        }
        if (picoquic_save_retry_tokens(qclient, token_file)) {
            printf("Could not save tokens in <%s>\n", token_file);
        }
    }

    if (qd_client != NULL) {
        quicdoq_demo_client_reset_context(qd_client, &client_ctx);
        quicdoq_delete(qd_client);
    }

    if (fd != INVALID_SOCKET) {
        SOCKET_CLOSE(fd);
    }

    if (F_log != NULL) {
        picoquic_file_close(F_log);
    }

    return ret;
}

/* Init a client query from the text query */
int quicdoq_demo_client_init_query(quicdoq_query_ctx_t* query_ctx, char const* client_query_text)
{
    /* Parse txt query into text & rr type */
    int ret = 0;
    char name[256];
    int l_n;
    int i_rr = -1;
    uint16_t rr_type = 1; /* Default to "A" */

    for (l_n = 0; l_n < 256; l_n++) {
        if (client_query_text[l_n] == ':') {
            name[l_n] = 0;
            i_rr = l_n + 1;
            break;
        }
        else if (client_query_text[l_n] == 0) {
            name[l_n] = 0;
            break;
        }
        else {
            name[l_n] = client_query_text[l_n];
        }
    }

    if (l_n >= 256) {
        ret = -1;
    }
    else if (i_rr > 0) {
        /* Get rr type from text */
        if ((rr_type = quicdoq_get_rr_type(&client_query_text[i_rr])) == UINT16_MAX) {
            ret = -1;
        }
    }
        
    /* Create query context in client ctx */
    if (ret == 0) {
        uint8_t* query_end = quicdog_format_dns_query(query_ctx->query, query_ctx->query + query_ctx->query_max_size, name, 0, 1, rr_type, query_ctx->response_max_size);

        if (query_end == NULL) {
            ret = -1;
        }
        else {
            query_ctx->query_length = (uint16_t)(query_end - query_ctx->query);
        }
    }

    return ret;
}

/* Creation of a client context from a list of text queries */

int quicdoq_demo_client_init_context(quicdoq_ctx_t* qd_client, quicdoq_demo_client_ctx_t * client_ctx, int nb_client_queries, char const** client_query_text,
    char const * server_name, struct sockaddr* server_addr, struct sockaddr* client_addr, uint64_t current_time)
{
    int ret = 0;
    memset(client_ctx, 0, sizeof(quicdoq_demo_client_ctx_t));

    client_ctx->start_time = current_time;

    client_ctx->query_ctx = (quicdoq_query_ctx_t**)malloc(sizeof(quicdoq_query_ctx_t*) * nb_client_queries);
    client_ctx->is_query_complete = (int *)malloc(sizeof(int) * nb_client_queries);

    if (client_ctx->query_ctx == NULL || client_ctx->is_query_complete == NULL) {
        ret = -1;
    }
    else {
        client_ctx->nb_client_queries = (uint16_t)nb_client_queries;
        memset(client_ctx->query_ctx, 0, sizeof(quicdoq_query_ctx_t*) * nb_client_queries);
        memset(client_ctx->is_query_complete, 0, sizeof(int) * nb_client_queries);

        for (int i = 0; ret == 0 && i < nb_client_queries; i++) {
            client_ctx->query_ctx[i] = quicdoq_create_query_ctx(QUICDOQ_MAX_STREAM_DATA, QUICDOQ_MAX_STREAM_DATA);
            if (client_ctx->query_ctx[i] == NULL) {
                ret = -1;
            }
            else {
                client_ctx->query_ctx[i]->server_name = server_name; 
                client_ctx->query_ctx[i]->server_addr = server_addr;
                client_ctx->query_ctx[i]->client_addr = client_addr; 
                client_ctx->query_ctx[i]->query_id = (uint16_t)i;
                client_ctx->query_ctx[i]->client_cb = quicdoq_demo_client_cb;
                client_ctx->query_ctx[i]->client_cb_ctx = client_ctx;
                ret = quicdoq_demo_client_init_query(client_ctx->query_ctx[i], client_query_text[i]);
            }
        }
    }

    for (int i = 0; ret == 0 && i < nb_client_queries; i++) {
        ret = quicdoq_post_query(qd_client, client_ctx->query_ctx[i]);
    }

    return ret;
}

void quicdoq_demo_client_reset_context(quicdoq_ctx_t* qd_client, quicdoq_demo_client_ctx_t * client_ctx)
{
    if (client_ctx->query_ctx != NULL) {
        for (size_t i = 0; i < client_ctx->nb_client_queries; i++) {
            if (client_ctx->query_ctx[i] != NULL) {
                (void)quicdoq_cancel_query(qd_client, client_ctx->query_ctx[i]);
                quicdoq_delete_query_ctx(client_ctx->query_ctx[i]);
                client_ctx->query_ctx[i] = NULL;
            }
        }
        if (client_ctx->is_query_complete != NULL) {
            free(client_ctx->is_query_complete);
        }
        free(client_ctx->query_ctx);
        client_ctx->query_ctx = NULL;
    }
}

void quicdoq_demo_print_response(quicdoq_query_ctx_t* query_ctx)
{
    char query_out[2048];
    size_t next;
    uint8_t* text_start = (uint8_t *)query_out;

    next = quicdoq_parse_dns_query(query_ctx->response, query_ctx->response_length, 0, (uint8_t **)&text_start,
        (uint8_t*)query_out + sizeof(query_out));

    if (text_start == NULL) {
        fprintf(stdout, "Could not parse the response to query #%" PRIu64 "\n", query_ctx->query_id);
    }
    else {
        *text_start = 0;
        fprintf(stdout, "Parsed %zu bytes out of %zu:\n%s\n", next, query_ctx->response_length, query_out);
    }
}

/* Client call back and submit function for tests
 */

int quicdoq_demo_client_cb(
    quicdoq_query_return_enum callback_code,
    void* callback_ctx,
    quicdoq_query_ctx_t* query_ctx,
    uint64_t current_time)
{
    int ret = 0;
    quicdoq_demo_client_ctx_t* client_ctx = (quicdoq_demo_client_ctx_t*)callback_ctx;
    uint16_t qid = (uint16_t) query_ctx->query_id;

    if (qid > client_ctx->nb_client_queries) {
        ret = -1;
    }
    else {
        fprintf(stdout, "Query #%d completes after %" PRIu64 "us with code %d\n",
            qid, current_time - client_ctx->start_time, callback_code);
        client_ctx->is_query_complete[qid] = 1;
        client_ctx->all_queries_served = 1;
        for (uint16_t i = 0; i < client_ctx->nb_client_queries; i++) {
            if (!client_ctx->is_query_complete[i]) {
                client_ctx->all_queries_served = 0;
                break;
            }
        }
        switch (callback_code) {
        case quicdoq_response_complete: /* The response to the current query arrived. */
            /* tabulate completed  & completion time */
            /* Display query result */
            quicdoq_demo_print_response(query_ctx);
            break;
        case quicdoq_response_cancelled: /* The response to the current query was cancelled by the peer. */
            /* tabulate cancelled & cancel time */
            fprintf(stdout, "Query #%d was cancelled.\n", qid);
            break;
        case quicdoq_query_failed:  /* Query failed for reasons other than cancelled. */
            /* tabulate failed & fail time  */
            fprintf(stdout, "Query #%d failed.\n", qid);
            break;
        default: /* callback code not expected on client */
            fprintf(stdout, "Unexpected return code.\n");
            ret = -1;
            break;
        }
    }

    return ret;
}
