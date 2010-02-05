/* Copyright (c) 2005-2010, Michael Santos <michael.santos@gmail.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * Neither the name of the author nor the names of its contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/* 
 * rst: TCP connect reset utility
 *
 * Aggressively resets TCP connections using TCP RST's or
 * ICMP.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sys/param.h>

#include <pcap.h>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#include <libnet.h>

#define RST_BUILD   "0.2"

#define PCAP_ERRBUF(x) do { \
    if ((x) == NULL) \
        errx(EXIT_FAILURE, "%s: %s", #x, errbuf); \
} while (0);

#define ISNULL(x) do { \
    if ((x) == NULL) \
        errx(EXIT_FAILURE, "%s", #x); \
} while (0);

#define ISLTZERO(x) do { \
    if ((x) < 0) \
        errx(EXIT_FAILURE, "%s", #x); \
} while (0);

#define PCAP_ERR(x) do { \
    if ((x) != 0) \
        errx(EXIT_FAILURE, "%s: %s", #x, pcap_geterr(p)); \
} while (0);

#define LIBNET_ERR(x) do { \
    if ((x) == -1) { \
        libnet_destroy(rst->l); \
        errx(EXIT_FAILURE, "%s: %s", #x, libnet_geterror(rst->l)); \
    } \
} while (0);

#define PAIR(x,y,z) ((x) == 0 ? (y) : (z))

#define NLADD(x,y) (ntohl(htonl(x)+y))

#define MAXWIDTH    60

extern char *__progname;

#define SNAPLEN     60
#define PROMISC     1   /* true */
#define TIMEOUT     500 /* ms */
#define PCAP_FILT   "tcp"
#define MAXFILT     256
#define ICMP_PKTLEN      8   /* 64 bits of original packet returned in ICMP packet */

#define RST_USER    "nobody"
#define RST_GROUP   "nobody"
#define RST_DIR     "/var/chroot/rst"

#define MICROSECONDS    1000000

enum {
    RST_TCP_RST = 1,    /* TCP RST */
    RST_ICMP    = 2,    /* ICMP Unreachable */
};

enum {
    ICMP_SRC_HOST,  /* Use the host as the ICMP source address */
    ICMP_SRC_GW,    /* Use the gateway as the ICMP source address */           
};

typedef struct {
    char *dev;
    u_char *pkt;
    pcap_t *p;
    libnet_t *l;
    u_int8_t flags;
    useconds_t sleep_for;
    char *myip;
    struct {
        u_int8_t type;
        u_int8_t code;
        u_int8_t src;
    } icmp;
} pkt_t;

libnet_t *rst_net_open(char *dev);
int rst_net_init(libnet_t *l);
int rst_net_send(libnet_t *l);
void rst_net_check(pkt_t *rst);
int rst_net_close(libnet_t *l);

int rst_pcap_init(pkt_t *rst, char *host, in_port_t port, u_int8_t exclude);
pcap_t *rst_pcap_open(char *dev);
int rst_pcap_run(pkt_t *rst);
int rst_pcap_close(pcap_t *p);

void rst_tcp_send(pkt_t *rst);

int rst_icmp_check(u_int8_t type, u_int8_t code);
void rst_icmp_send(pkt_t *rst);
void rst_icmp_type(pkt_t *rst);

int rst_priv_drop(char *user, char *group, char *path);

void usage(void);

