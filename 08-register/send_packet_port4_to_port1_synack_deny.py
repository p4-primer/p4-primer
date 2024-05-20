#!/usr/bin/env python3

import sys
import random

from scapy.all import Ether, IP, TCP, sendp

def main():
    
    ifname="veth5"
    pkt = Ether(dst="10:22:33:44:55:66", src="10:22:33:44:55:77") / IP(ttl=64, src="1.1.4.4", dst="1.1.1.2") / TCP(dport=10002, sport=80, flags='SA', seq=4000, ack=5000)
    pkt.show2()
    sendp(pkt, iface=ifname, verbose=False)

if __name__ == '__main__':
    main()
