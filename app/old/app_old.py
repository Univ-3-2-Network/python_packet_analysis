import sys
from scapy.all import *

if __name__ == '__main__':
    # p=sr1(IP(dst=sys.argv[1])/ICMP())
    p=sr1(IP(dst="prayanne.co.kr")/ICMP()/"GET /index.html HTTP/1.0 \n\n")
    # if p:
    #     p.show()
    #     packet_callback(p)
    
    # a=Ether()/IP(dst="www.tukorea.ac.kr")/TCP()/"GET /index.html HTTP/1.0 \n\n"
    # hexdump(a)
    # send(a, return_packets=True)


def packet_callback(packet):
    print(packet.show())
    sniff(prn=packet_callback, count=10) #10개의 패킷 캡처