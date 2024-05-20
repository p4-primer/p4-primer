#!/usr/bin/env python3

from scapy.all import Ether, IP, TCP, sendp

def main():
    
    ifname="veth1"
    print("sending a packet on interface %s" % (ifname))
    pkt = Ether(dst="10:22:33:44:55:66", src="aa:bb:cc:dd:ee:01") / IP(ttl=64, src="1.1.1.2", dst="4.4.4.4") / TCP(dport=80, sport=10000)
    pkt.show2()
    sendp(pkt, iface=ifname, verbose=False)

if __name__ == '__main__':
    main()
