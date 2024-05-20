#!/usr/bin/env python3

import sys
import random

from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp

def main():
    
    ifname="veth1"
    pkt = Ether(dst="10:22:33:44:55:66", src="aa:bb:cc:dd:ee:01") / IP(ttl=128, id=1, src="1.1.1.2", dst="2.2.2.3") / UDP(dport=80, sport=8080) / ("B" * 58)
    sendp(pkt, iface=ifname, verbose=False, inter=1/1000)

if __name__ == '__main__':
    main()
