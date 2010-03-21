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
#include "rst.h"


/* Send a RST to the source and destination ports */
    void
rst_tcp_send(pkt_t *rst)
{
    struct ether_header *eh = NULL;
    struct ip *ih = NULL;
    struct tcphdr *th = NULL;

    int pair = 0;
    char *state = NULL;

    eh = (struct ether_header *)rst->pkt;
    ih = (struct ip *)(rst->pkt + sizeof(struct ether_header));
    th = (struct tcphdr *)(rst->pkt + sizeof(struct ether_header) + sizeof(struct ip));

    /* Don't RST a RST; only RST a session in ACK */
    if ( (th->th_flags & TH_RST) || \
            !((th->th_flags & TH_ACK) || (th->th_flags & TH_SYN)))
        return;

    /* Send out a pair of RST's to source and to destination */
    for (pair = 0; pair < 2; pair++) {
        LIBNET_ERR(libnet_build_tcp(
                    PAIR(pair, ntohs(th->th_sport), ntohs(th->th_dport)),     /* Source port */
                    PAIR(pair, ntohs(th->th_dport), ntohs(th->th_sport)),     /* Destination port */
                    PAIR(pair, ntohl(th->th_seq), ntohl(th->th_ack)),         /* Sequence number */
                    PAIR(pair, ntohl(th->th_ack), ( (th->th_ack == 0) ? (ntohl(th->th_seq) + ntohs(ih->ip_len)) : ntohl(th->th_seq))), /* Acknowledgement number */
                    TH_RST,
                    ntohs(th->th_win),                                 /* XXX believe the packets window size? */
                    0,                                          /* auto checksum */
                    0,                                          /* XXX urg pointer */
                    LIBNET_TCP_H,                               /* total packet length */
                    NULL,                                       /* payload */
                    0,                                          /* payload size */
                    rst->l,                                     /* libnet context */
                    0                                       /* ptag */
                    ));

        LIBNET_ERR(libnet_build_ipv4(
                    LIBNET_IPV4_H + LIBNET_TCP_H,               /* no payload */
                    0,                                          /* TOS */
                    ntohs(ih->ip_id),                                  /* IP ID */
                    0,                                          /* Frag */
                    ih->ip_ttl,                                 /* XXX TTL, from the packet? */
                    IPPROTO_TCP,                                /* Protocol */
                    0,                                          /* auto checksum */
                    PAIR(pair, ih->ip_src.s_addr, ih->ip_dst.s_addr),         /* source */
                    PAIR(pair, ih->ip_dst.s_addr, ih->ip_src.s_addr),         /* destination */
                    NULL,                                       /* payload */
                    0,                                          /* payload size */
                    rst->l,                                     /* libnet context */
                    0                                        /* libnet ptag */
                    ));

        state =  ( (libnet_write(rst->l) == -1) ? "x" : "R");
        (void)fprintf(stdout, "[%s] SRC = %s:%u DST = %s:%u\n", state,
                      libnet_addr2name4(PAIR(pair, ih->ip_src.s_addr, ih->ip_dst.s_addr), LIBNET_DONT_RESOLVE),
                      PAIR(pair, ntohs(th->th_sport), ntohs(th->th_dport)),
                      libnet_addr2name4(PAIR(pair, ih->ip_dst.s_addr, ih->ip_src.s_addr), LIBNET_DONT_RESOLVE),
                      PAIR(pair, ntohs(th->th_dport), ntohs(th->th_sport)));

        (void)fflush(stdout);

        usleep(rst->sleep_for);
    }
}
