MT_DEBUG = -g
MT_LIBS  = -lpcap

MT_TOOLS_OBJ = mt_mda.o \
               mt_nd.o \
               mt_ping.o \
               mt_traceroute.o

MT_BUILD_OBJ = checksum.o \
               packet.o \
               packet_helper.o \
               pdu_arp.o \
               pdu_data.o \
               pdu_eth.o \
               pdu_icmpv4.o \
               pdu_icmpv6.o \
               pdu_ipv4.o \
               pdu_ipv6.o \
               pdu_udp.o \
               pdu_tcp.o

MT_UTILS_OBJ = addr.o \
			   dst.o \
               iface.o \
               list.o \
               match.o \
               util.o

MT_OBJ = mt.o link.o route.o probe.o buffer.o args.o \
         $(MT_TOOLS_OBJ) $(MT_BUILD_OBJ) $(MT_UTILS_OBJ)

all: mtraceroute

mtraceroute: $(MT_OBJ)
	gcc -o $@ $^ $(MT_DEBUG) $(MT_LIBS)

%.o: %.c
	gcc -o $@ -c $<

clean:
	rm -f mtraceroute *.o
