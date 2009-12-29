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

    libnet_t *
rst_net_open(char *dev)
{
    libnet_t *l = NULL;
    char buf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(LIBNET_RAW4, dev, buf);

    if (l == NULL)
        (void)fprintf(stderr, "libnet_init: %s", buf);
    return (l);
}

int
rst_net_init(libnet_t *l)
{
    return (0);
}

void
rst_net_check(pkt_t *rst)
{
    if (rst->flags & RST_ICMP) {
        ISLTZERO(rst_icmp_check(rst->icmp.type, rst->icmp.code));
        rst_icmp_type(rst);
    }
    else if (rst->flags & RST_TCP_RST) {
        (void)fprintf(stdout, "TCP RST connection storm selected.\n");
    }
}

    int
rst_net_close(libnet_t *l)
{
    libnet_destroy(l);
    return (0);
}

