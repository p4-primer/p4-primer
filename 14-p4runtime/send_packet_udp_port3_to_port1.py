#!/usr/bin/env python3

import sys
import random

from scapy.all import Ether, IP, TCP, UDP, ICMP, sendp

def main():
    
    ifname="veth5"
    pkt = Ether(dst="aa:bb:cc:dd:ee:01", src="10:22:33:44:55:68") / IP(ttl=64, id=65535, src="1.1.1.4", dst="1.1.1.2") / UDP(dport=80, sport=8080) / ("B" * 58)
    sendp(pkt, iface=ifname, verbose=False, inter=1/1000)

if __name__ == '__main__':
    main()
