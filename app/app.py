import sys
from scapy.all import *

if __name__ == '__main__':
    p=sr1(IP(dst=sys.argv[1])/ICMP())
    if p:
        # p.show()
        packet_callback(p)


def packet_callback(packet):
    print(packet.show())
    sniff(prn=packet_callback, count=10) #10개의 패킷 캡처