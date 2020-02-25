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
#include "picoquic_utils.h"
#include "quicdoq.h"

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

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

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#endif

uint16_t default_server_port = 7763;

void usage()
{
    fprintf(stderr, "Quicdoq demo client and server\n");
    fprintf(stderr, "Client: quicdoq_app <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "Client: quicdoq_app <options> -p port -D dns-server\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c file               cert file (default: %s)\n", SERVER_CERT_FILE);
    fprintf(stderr, "  -e if                 Send on interface (default: -1)\n");
    fprintf(stderr, "                           -1: receiving interface\n");
    fprintf(stderr, "                            0: routing lookup\n");
    fprintf(stderr, "                            n: ifindex\n");
    fprintf(stderr, "  -h                    This help message\n");
    fprintf(stderr, "  -i <src mask value>   Connection ID modification: (src & ~mask) || val\n");
    fprintf(stderr, "                        Implies unconditional server cnx_id xmit\n");
    fprintf(stderr, "                          where <src> is int:\n");
    fprintf(stderr, "                            0: picoquic_cnx_id_random\n");
    fprintf(stderr, "                            1: picoquic_cnx_id_remote (client)\n");
    fprintf(stderr, "                            2: same as 0, plus encryption of unmasked data\n");
    fprintf(stderr, "                            3: same as 0, plus encryption of all data\n");
    fprintf(stderr, "                        val and mask must be hex strings of same length, 4 to 18\n");
    fprintf(stderr, "  -k file               key file (default: %s)\n", SERVER_KEY_FILE);
    fprintf(stderr, "  -K file               ESNI private key file (default: don't use ESNI)\n");
    fprintf(stderr, "  -E file               ESNI RR file (default: don't use ESNI)\n");
    fprintf(stderr, "  -l file               Log file, Log to stdout if file = \"n\". No logging if absent.\n");
    fprintf(stderr, "  -L                    Log all packets. If absent, log stops after 100 packets.\n");
    fprintf(stderr, "  -p port               server port (default: %d)\n", default_server_port);
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -n sni                sni (default: server name)\n");
    fprintf(stderr, "  -a alpn               alpn (default: doq)\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -t file               root trust file\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff000012\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");
    fprintf(stderr, "  -I length             Length of CNX_ID used by the client, default=8\n");
    fprintf(stderr, "  -g cc_log_dir         log congestion control traces in specified dir\n");
    fprintf(stderr, "  -G cc_algorithm       Use the specified congestion control algorithm:\n");
    fprintf(stderr, "                        reno, cubic, bbr or fast. Defaults to bbr.\n");

    fprintf(stderr, "\nIn client mode, the scenario provides the list of names to be resolved\n");
    fprintf(stderr, "and the recrd type. The syntax is:\n");
    fprintf(stderr, "  *{name:rrtype;}\n");
    fprintf(stderr, "If no scenario is specified, the client looks for www.example.com:A.\n");
    fprintf(stderr, "\nIn server mode, the queries are sent over UDP to the backend DNS server\n");
    fprintf(stderr, "\nspecified in the -D argument.\n");

    exit(1);
}


int main()
{
}