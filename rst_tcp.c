/* 
 * rst: TCP connect reset utility
 *
 * Aggressively resets TCP connections using TCP RST's or
 * ICMP.
 *
 * Copyright (c) 2005-2007 Michael Santos <michael.santos@gmail.com>
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
                    PAIR(pair, th->th_sport, th->th_dport),     /* Source port */
                    PAIR(pair, th->th_dport, th->th_sport),     /* Destination port */
                    PAIR(pair, th->th_seq, th->th_ack),         /* Sequence number */
                    PAIR(pair, th->th_ack, ( (th->th_ack == 0) ? (th->th_seq + ih->ip_len) : th->th_seq)), /* Acknowledgement number */
                    TH_RST,
                    th->th_win,                                 /* XXX believe the packets window size? */
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
                    ih->ip_id,                                  /* IP ID */
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
                      PAIR(pair, th->th_sport, th->th_dport),
                      libnet_addr2name4(PAIR(pair, ih->ip_dst.s_addr, ih->ip_src.s_addr), LIBNET_DONT_RESOLVE),
                      PAIR(pair, th->th_dport, th->th_sport));

        (void)fflush(stdout);

        usleep(rst->sleep_for);
    }
}
