#!/usr/bin/env python3

from scapy.all import Ether, IP, UDP, sendp, Raw

def main():
    
    ifname="veth1"
    print("sending a packet on interface %s" % (ifname))
    pkt = Ether(dst="aa:bb:cc:dd:ee:02", src="aa:bb:cc:dd:ee:01") / IP(ttl=64, src="192.168.1.10", dst="192.168.1.11") / UDP(dport=8001, sport=10000) / Raw(load="111111111111111111")
    pkt.show2()
    sendp(pkt, iface=ifname, verbose=False)

if __name__ == '__main__':
    main()
