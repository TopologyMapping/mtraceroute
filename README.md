# mtraceroute (alpha)

Multipath traceroute (`mtraceroute`) is based on and implements similar functionality to [Paris traceroute](https://paris-traceroute.net). It keeps the flow identifier of probe packets fixed to avoid triggering traffic load balancing in Internet routes whenever possible. Moreover, `mtraceroute` implements the [Multipath Detection Algorithm](https://paris-traceroute.net/publications), which identifies routers that perform load balancing on the route from a source to a destination. `mtraceroute` systematically varies probe packets’ headers to classify load balancing behavior. 

## Download and build
```
% git clone https://github.com/TopologyMapping/mtraceroute
% autoreconf --install
% ./configure
% make
```

## Dependencies

Linux, gcc, libpcap and root access

## Usage
```
mtraceroute ADDRESS [-c command] [-w wait] [-z send-wait]

    -c command: traceroute|ping|mda, default: traceroute
    -r number of retries: default: 2
    -w seconds to wait for answer: default: 1
    -z milliseconds to wait between sends: default: 20
            
    MDA: -c mda [-a confidence] [-f flow-id] [-t max-ttl]

        -a confidence level in %: 90|95|99, default: 95
        -f what flow identifier to use, some values depends on
           the type of the address
           IPv4: icmp-chk, icmp-dst, udp-sport, udp-dst, tcp-sport, tcp-dst
                 Default: udp-sport
           IPv6: icmp-chk, icmp-dst, icmp-fl, icmp-tc, udp-sport, udp-dst,
                 udp-fl, udp-tc, tcp-sport, tcp-dst, tcp-fl, tcp-tc
                 Default: udp-sport
        -t max number of hops to probe: default: 30

    TRACEROUTE: -c traceroute [-t max-ttl] [-m method] [-p probes-at-once]

        -t max number of hops to probe: default: 30
        -m method of probing: icmp|udp|tcp, default: icmp
        -p number of probes to send at once: default: 3

    PING: -c ping [-n send-probes]

        -n number of probes to send: default: 5
```

## Contributing

Please check https://github.com/TopologyMapping/mtraceroute/issues
