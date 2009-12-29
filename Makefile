LIBNET_CONFIG=/usr/pkg/bin/libnet11-config

GCC=gcc
RM=/bin/rm
APP=rst
LDFLAGS=-L/usr/pkg/lib $(LIBNET)
CFLAGS=-I/usr/pkg/include
LIBS=-lpcap -lnet

rst:
	$(GCC) $(CFLAGS) $(LDFLAGS) $(LIBS) \
		`$(LIBNET_CONFIG) --libs` \
		`$(LIBNET_CONFIG) --cflags` \
		`$(LIBNET_CONFIG) --defines` \
		-g -Wall -o $(APP) $(APP)_priv.c $(APP)_net.c $(APP)_pcap.c $(APP)_tcp.c $(APP)_icmp.c $(APP).c

clean:
	-@$(RM) $(APP)
