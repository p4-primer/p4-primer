#!/usr/bin/env python3

import sys
import random

from scapy.all import Ether, IP, TCP, sendp

def main():
    
    ifname="veth1"
    for i in range(1, 1001, 1):
        src_port = random.randint(20000, 40000)
        pkt = Ether(dst="10:22:33:44:55:66", src="aa:bb:cc:dd:ee:01") / IP(ttl=64, src="1.1.1.2", dst="2.2.2.3") / TCP(dport=80, sport=src_port)
        sendp(pkt, iface=ifname, verbose=False)

if __name__ == '__main__':
    main()
