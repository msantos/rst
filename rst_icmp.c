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

#ifndef ICMP_PARAMPROB_LENGTH
#define ICMP_PARAMPROB_LENGTH 2
#endif /* ICMP_PARAMPROB_LENGTH */

    int
rst_icmp_check(u_int8_t type, u_int8_t code)
{
    switch (type) {
        case ICMP_UNREACH:
            if (code > ICMP_UNREACH_PRECEDENCE_CUTOFF) {
                (void)fprintf(stderr, "ICMP code must < %d", ICMP_UNREACH_PRECEDENCE_CUTOFF);
                return (-1);
            }
            break;
        case ICMP_REDIRECT:
            if (code > ICMP_REDIRECT_TOSHOST) {
                (void)fprintf(stderr, "ICMP code must < %d", ICMP_REDIRECT_TOSHOST);
                return (-1);
            }
            break;
        case ICMP_TIMXCEED:
            if (code > ICMP_TIMXCEED_REASS) {
                (void)fprintf(stderr, "ICMP code must < %d", ICMP_TIMXCEED_REASS);
                return (-1);
            }
            break;
        case ICMP_PARAMPROB:
            if (code > ICMP_PARAMPROB_LENGTH) {
                (void)fprintf(stderr, "ICMP code must < %d", ICMP_PARAMPROB_LENGTH);
                return (-1);
            }
            break;
        case ICMP_SOURCEQUENCH:
            break;
        default:
            (void)fprintf(stderr, "Unsupported icmp type: %d\n", type);
            return (-1);
    }
    return (0);
}

    void
rst_icmp_type (pkt_t *rst)
{
    char *icmp_descr = "(unknown ICMP)";

    (void)fprintf(stdout, "icmp.type = %u, icmp.code = %u\n", rst->icmp.type, rst->icmp.code);

    (void)fprintf(stdout, "[%s] ", __progname);

    /* How do we get our gateway address? We will not see the external address
     * of our gateway.
     */
    rst->icmp.src = ICMP_SRC_HOST;

    switch (rst->icmp.type) {
        case ICMP_UNREACH:
            switch (rst->icmp.code) {
                case 0:
                    icmp_descr = "ICMP_UNREACH_NET (bad net)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case 1:
                    icmp_descr = "ICMP_UNREACH_HOST (bad host)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case 2:
                    icmp_descr = "ICMP_UNREACH_PROTOCOL (bad protocol)";
                    break;
                case 3:
                    icmp_descr = "ICMP_UNREACH_PORT (bad port)";
                    break;
                case 4:
                    icmp_descr = "ICMP_UNREACH_NEEDFRAG (IP_DF caused drop)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case 5:
                    icmp_descr = "ICMP_UNREACH_SRCFAIL (src route failed)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case 6:
                    icmp_descr = "ICMP_UNREACH_NET_UNKNOWN (unknown net)";
                    break;
                case 7:
                    icmp_descr = "ICMP_UNREACH_HOST_UNKNOWN (unknown host)";
                    break;
                case 8:
                    icmp_descr = "ICMP_UNREACH_ISOLATED (src host isolated)";
                    break;
                case 9:
                    icmp_descr = "ICMP_UNREACH_NET_PROHIB (prohibited access)";
                    break;
                case 10:
                    icmp_descr = "ICMP_UNREACH_HOST_PROHIB (prohibited access)";
                    break;
                case 11:
                    icmp_descr = "ICMP_UNREACH_TOSNET (bad tos for net)";
                    break;
                case 12:
                    icmp_descr = "ICMP_UNREACH_TOSHOST (bad tos for host)";
                    break;
                case 13:
                    icmp_descr = "ICMP_UNREACH_FILTER_PROHIB (admin prohib)";
                    break;
                case 14:
                    icmp_descr = " ICMP_UNREACH_HOST_PRECEDENCE (host prec vio.)";
                    break;
                case 15:
                    icmp_descr = "ICMP_UNREACH_PRECEDENCE_CUTOFF (prec cutoff)";
                    break;
                default:
                    errx(EXIT_FAILURE, "Invalid ICMP unreachable code selected.\n");
            }
            break;
        case ICMP_TIMXCEED:
            switch (rst->icmp.code) {
                case ICMP_TIMXCEED_INTRANS:
                    icmp_descr = "ICMP_TIMXCEED_INTRANS (ttl==0 in transit)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case ICMP_TIMXCEED_REASS:
                    icmp_descr = "ICMP_TIMXCEED_REASS (ttl==0 in reass)";
                    break;
                default:
                    errx(EXIT_FAILURE, "Invalid ICMP time exceeded code selected.\n");
            }
            break;
        case ICMP_REDIRECT:
            switch (rst->icmp.code) {
                case ICMP_REDIRECT_NET:
                    icmp_descr = "ICMP_REDIRECT_NET (for network)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case ICMP_REDIRECT_HOST:
                    icmp_descr = "ICMP_REDIRECT_HOST (for host)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case ICMP_REDIRECT_TOSNET:
                    icmp_descr = "ICMP_REDIRECT_TOSNET (for tos and net)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                case ICMP_REDIRECT_TOSHOST:
                    icmp_descr = "ICMP_REDIRECT_TOSHOST (for tos and host)";
                    rst->icmp.src = ICMP_SRC_GW;
                    break;
                default:
                    errx(EXIT_FAILURE, "Invalid ICMP redirect code selected.\n");
            }
            break;
    }
    (void)fprintf(stdout, "ICMP %s storm selected\n", icmp_descr);
}

/* Send an ICMP packet, such as host unreachable, to the source and destination addresses */
    void
rst_icmp_send(pkt_t *rst)
{
    struct ip *ih = NULL;
    struct tcphdr *th = NULL;

    int pair = 0;
    char *state = NULL;

    size_t icmp_len = 0;

    ih = (struct ip *)(rst->pkt + sizeof(struct ether_header));
    th = (struct tcphdr *)(rst->pkt + sizeof(struct ether_header) + sizeof(struct ip));

    /* The interface described in "Building Open Source Network Security Tools"
     * appears to be deprecated. The new interface tunnels an IPv4 packet
     * within the ICMP unreachable using the libnet context.
     */
    switch (rst->icmp.type) {

        /* RFC 792
         *
         * Type 3
         *
         * Codes 0, 1, 4, and 5 may be received from a gateway.  Codes 2 and
         * 3 may be received from a host.
         *
         *  0 = net unreachable;
         *  1 = host unreachable;
         *  2 = protocol unreachable;
         *  3 = port unreachable;
         *  4 = fragmentation needed and DF set;
         *  5 = source route failed.
         *
         */
        case ICMP_UNREACH:
            icmp_len = LIBNET_ICMPV4_UNREACH_H + LIBNET_IPV4_H + ICMP_PKTLEN;
            LIBNET_ERR(libnet_build_icmpv4_unreach(
                        rst->icmp.type,                             /* ICMP type, e.g. 3 (Unreachable) */
                        rst->icmp.code,                             /* ICMP code, e.g., 1 (Bad Host) */
                        0,                                          /* auto checksum */
                        (u_char *)ih,                               /* payload */
                        LIBNET_IPV4_H + ICMP_PKTLEN,                /* payload size */
                        rst->l,                                     /* libnet context */
                        0                                           /* ptag */
                        ));
            break;

            /*
             * Type 5
             *
             * Codes 0, 1, 2, and 3 may be received from a gateway.
             *
             *  0 = Redirect datagrams for the Network.
             *  1 = Redirect datagrams for the Host.
             *  2 = Redirect datagrams for the Type of Service and Network.
             *  3 = Redirect datagrams for the Type of Service and Host.
             *
             */
        case ICMP_REDIRECT:
            icmp_len = LIBNET_ICMPV4_REDIRECT_H;
            LIBNET_ERR(libnet_build_icmpv4_unreach(
                        rst->icmp.type,
                        rst->icmp.code,
                        0,
                        (u_char *)ih,
                        LIBNET_IPV4_H + ICMP_PKTLEN,
                        rst->l,
                        0));

            break;

            /*
             * Type 11
             *
             * Code 0 may be received from a gateway.  Code 1 may be received
             * from a host.
             *
             * 0 = time to live exceeded in transit
             * 1 = fragment reassembly time exceeded
             *
             */
        case ICMP_TIMXCEED:
            icmp_len = LIBNET_ICMPV4_TIMXCEED_H + LIBNET_IPV4_H + ICMP_PKTLEN;
            LIBNET_ERR(libnet_build_icmpv4_timeexceed(
                        rst->icmp.type,
                        rst->icmp.code,
                        0,
                        (u_char *)ih,
                        LIBNET_IPV4_H + ICMP_PKTLEN,
                        rst->l,
                        0));
            break;

        case ICMP_PARAMPROB:
        case ICMP_SOURCEQUENCH:
            errx(EXIT_FAILURE, "Not supported by libnet.");
            break;

        default:
            errx(EXIT_FAILURE, "ICMP type %d is not supported yet\n",
                    rst->icmp.type);
    }

    LIBNET_ERR(libnet_build_ipv4(
                LIBNET_IPV4_H + icmp_len,                   /* payload size */
                IPTOS_LOWDELAY | IPTOS_THROUGHPUT,          /* TOS */
                ih->ip_id+1,                                /* IP ID */
                0,                                          /* Frag */
                64,                                         /* TTL */
                IPPROTO_ICMP,                               /* Protocol */
                0,                                          /* auto checksum */
                ih->ip_dst.s_addr,                          /* source */
                ih->ip_src.s_addr,                          /* destination */
                NULL,                                       /* payload */
                0,                                          /* payload size */
                rst->l,                                     /* libnet context */
                0                                           /* libnet ptag */
                ));

    state = ((libnet_write(rst->l) == -1) ? "x" : "I");
    (void)fprintf(stdout, "[%s] SRC = %15s:%-6u DST = %15s:%-6u len = %d/%d\n", state,
                  libnet_addr2name4(PAIR(pair, ih->ip_src.s_addr, ih->ip_dst.s_addr), LIBNET_DONT_RESOLVE),
                  PAIR(pair, th->th_sport, th->th_dport),
                  libnet_addr2name4(PAIR(pair, ih->ip_dst.s_addr, ih->ip_src.s_addr), LIBNET_DONT_RESOLVE),
                  PAIR(pair, th->th_dport, th->th_sport), LIBNET_IPV4_H + (u_int32_t)icmp_len, ih->ip_len);

    (void)fflush(stdout);

    usleep(rst->sleep_for);
}

