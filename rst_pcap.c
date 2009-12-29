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
