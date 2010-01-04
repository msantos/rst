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
main(int argc, char *argv[])
{
    pkt_t *rst = NULL;

    int ch = 0;
    int exclude = 0;
    char *host = NULL;
    in_port_t port = 0;

    char *user = strdup(RST_USER);
    char *group = strdup(RST_GROUP);
    char *path = strdup(RST_DIR);

    ISNULL(rst = (pkt_t *)calloc(1, sizeof(pkt_t)));

    rst->flags = RST_TCP_RST;
    rst->icmp.type = ICMP_UNREACH;      /* Default is ICMP unreachable (type 3) */
    rst->icmp.code = ICMP_UNREACH_PORT; /* Default is ICMP port unreachable (code 3) */

    while ( (ch = getopt(argc, argv, "c:d:g:hH:i:Ip:rR:t:u:xX:")) != EOF) {
        switch (ch) {
            case 'c':               /* ICMP code */
                rst->icmp.code = (u_int8_t)atoi(optarg);
                rst->flags = RST_ICMP;
                break;
            case 'd':               /* chroot path */
                path = strdup(optarg);
                break;
            case 'g':               /* unprivileged group */
                group = strdup(optarg);
                break;
            case 'h':               /* Help */
                usage();
                break;
            case 'H':
                if (strlen(optarg) > MAXHOSTNAMELEN)
                    errx(EXIT_FAILURE, "Hostname too long");
                host = strdup(optarg);
                break;
            case 'i':               /* Use interface */
                rst->dev = strdup(optarg);
                break;
            case 'I':
                rst->flags = RST_ICMP;
                break;
            case 'p':               /* list of ports */
                port = (in_port_t)atoi(optarg);
                break;
            case 'r':
                rst->flags = RST_TCP_RST;   /* TCP RST */
                break;
            case 'R':
                rst->sleep_for = MICROSECONDS / (useconds_t)atoi(optarg);   /* Maximum number of packets sent per second */
                (void)fprintf(stderr, "[%s] Sleeping for %u usec between sending packets\n", __progname, rst->sleep_for);
                break;
            case 't':               /* ICMP type */
                rst->icmp.type = (u_int8_t)atoi(optarg);
                break;
            case 'u':               /* unprivileged user */
                user = strdup(optarg);
                break;
            case 'x':               /* Exclude our IP address */
                exclude = 1;    
                break;
            case 'X':               /* Exclude by specifying our IP address */
                exclude = 1;
                rst->myip = strdup(optarg);    
                break;
            default:
                usage();
                break;
        }
    }

    rst_net_check(rst);

    ISNULL(rst->l = rst_net_open(rst->dev));
    ISNULL(rst->p = rst_pcap_open(rst->dev));

    /* Drop privileges */
    if (rst_priv_drop(user, group, path) != 0)
        exit (EXIT_FAILURE);

    ISLTZERO(rst_pcap_init(rst, host, port, exclude));
    ISLTZERO(rst_pcap_run(rst));

    ISLTZERO(rst_net_close(rst->l));
    ISLTZERO(rst_pcap_close(rst->p));
    if (rst->dev)
        free(rst->dev);
    if (rst->myip)
        free(rst->myip);
    if (host)
        free(host);

    free(user);
    free(group);
    free(path);

    exit (EXIT_FAILURE);
}

    void
usage(void)
{
    (void)fprintf(stderr, "[%s v%s: Reset TCP connections]\n",
                  __progname, RST_BUILD);
    (void)fprintf(stderr, "Usage: %s [-h|-H <host>|-i <interface>|-I <icmp type>|-p <port>|-R <number>|-x|-X <ip>]\n"
            "-h               usage\n\n"
            "-x               exclude our IP address\n"
            "-X <IP Address>  specify an IP address to exclude\n\n"
            "-H <host>        hostname\n"
            "-p <port>        port to reset\n"
            "-i <interface>   interface\n"
            "-R <number>      rate limit, number of packets per second\n\n"
            "-d <path>        chroot path (default = %s)\n"
            "-u <user>        unprivliged user (default = %s)\n"
            "-g <group>       unprivilged group (default = %s)\n\n"
            "-c <ICMP code>   code to use for ICMP resets\n"
            "-I               reset using ICMP\n"
            "-t <ICMP type>   type to use for ICMP resets\n\n"
            "[Bug reports to michael.santos@gmail.com]\n",
            __progname, RST_DIR, RST_USER, RST_GROUP);
    exit (EXIT_FAILURE);
}
