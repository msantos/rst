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

    int
rst_pcap_init(pkt_t *rst, char *host, in_port_t port, u_int8_t exclude)
{
    char *filt = NULL;

    struct bpf_program fcode;
    char buf[PCAP_ERRBUF_SIZE];
    u_int32_t ipaddr = 0;
    u_int32_t ipmask = 0;
    int ret = 0;

    (void)memset(buf, 0, PCAP_ERRBUF_SIZE);

    ISNULL(filt = (char *)calloc(MAXFILT, 1));
    ret = snprintf(filt, MAXFILT, "%s", PCAP_FILT);
    if ( (ret < 0) || (ret > MAXFILT))
        errx(EXIT_FAILURE, "could not create pcap filter");

    if (pcap_lookupnet(rst->dev, &ipaddr, &ipmask, buf) == -1) {
        warnx("%s\n", buf);
        return (-1);
    }

    /* Exclude the sending IP's address */
    if (exclude == 1) {
        char *addr = NULL;

        addr = strdup(rst->myip ? rst->myip : libnet_addr2name4(ipaddr, LIBNET_DONT_RESOLVE));
        (void)snprintf(filt, MAXFILT, "%s and not host %s", filt, addr);
        free(addr);
    }

    /* RST specific port only */
    if (port != 0)
        (void)snprintf(filt, MAXFILT, "%s and port %d", filt, port);

    /* RST specific host only */
    if (host != NULL)
        (void)snprintf(filt, MAXFILT, "%s and host %s", filt, host);

    (void)fprintf(stdout, "[%s] Using filter: %s\n", __progname, filt);

    if (pcap_compile(rst->p, &fcode, filt, 1 /* optimize == true */, ipmask) != 0) {
        warnx("pcap_compile: %s", pcap_geterr(rst->p));
        return (-1);
    }

    if (pcap_setfilter(rst->p, &fcode) != 0) {
        warnx("pcap_setfilter: %s", pcap_geterr(rst->p));
        return (-1);
    }

    switch (pcap_datalink(rst->p)) {
        case DLT_IEEE802_11:
            (void)fprintf(stdout, "[%s] Link layer is 802.11\n", __progname);
            break;
        case DLT_EN10MB:
            (void)fprintf(stdout, "[%s] Link layer is ethernet\n", __progname);
            break;
        default:
            (void)fprintf(stdout, "[%s] Link layer is unsupported\n", __progname);
            break;
    }

    free(filt);
    return (0);
}

    int
rst_pcap_run(pkt_t *rst)
{
    struct pcap_pkthdr hdr;

    for ( ; ; ) {
        rst->pkt = (u_char *)pcap_next(rst->p, &hdr);
        if (rst->pkt == NULL)
            continue;

        if (rst->flags & RST_TCP_RST)
            rst_tcp_send(rst);
        else if (rst->flags & RST_ICMP)
            rst_icmp_send(rst);
    }
}

    pcap_t *
rst_pcap_open(char *dev)
{
    pcap_t *p = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL)
        PCAP_ERRBUF(dev = pcap_lookupdev(errbuf));

    (void)fprintf(stdout, "[%s] Using device: %s\n", __progname, dev);

    PCAP_ERRBUF(p = pcap_open_live(dev, SNAPLEN, PROMISC, TIMEOUT, errbuf));
    return (p);
}

    int
rst_pcap_close(pcap_t *p)
{
    if (p)
        pcap_close(p);
    return (0);
}
