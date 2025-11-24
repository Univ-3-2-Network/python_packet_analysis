from scapy.all import *

print(packet.show())

sniff(prn=packet_callback, count=10) #10개의 패킷 캡처