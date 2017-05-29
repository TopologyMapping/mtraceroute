bin_PROGRAMS = mtraceroute
mtraceroute_SOURCES = $(MT_OBJ_SRC) $(MT_TOOLS_SRC) $(MT_BUILD_SRC) \
		$(MT_UTILS_SRC)

MT_TOOLS_SRC = mt_mda.h mt_mda.c \
		mt_nd.h mt_nd.c \
		mt_ping.h mt_ping.c \
		mt_traceroute.h mt_traceroute.c

MT_BUILD_SRC = checksum.h checksum.c \
		packet.h packet.c \
		packet_helper.h packet_helper.c \
		pdu_arp.h pdu_arp.c \
		pdu_data.h pdu_data.c \
		pdu_eth.h pdu_eth.c \
		pdu_icmpv4.h pdu_icmpv4.c \
		pdu_icmpv6.h pdu_icmpv6.c \
		pdu_ipv4.h pdu_ipv4.c \
		pdu_ipv6.h pdu_ipv6.c \
		pdu_udp.h pdu_udp.c \
		pdu_tcp.h pdu_tcp.c

MT_UTILS_SRC = addr.h addr.c \
		dst.h dst.c \
		iface.h iface.c \
		list.h list.c \
		match.h match.c \
		util.h util.c

MT_OBJ_SRC = mt.h mt.c \
		link.h link.c \
		route.h route.c \
		probe.h probe.c \
		buffer.h buffer.c \
		args.h args.c

clean-local:
	-rm -rf *log.txt.* tags
