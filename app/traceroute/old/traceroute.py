# Importing Libraries
import socket
import struct
import time
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR, DNSRR,
    sr1, send, sniff, conf, AsyncSniffer
)
import argparse

# Traceroute Function
def traceroute(destination, max_hops=30, timeout=2):
    destination_ip = socket.gethostbyname(destination)
    port = 33434
    ttl = 1

    while True:
        # Creating the IP and UDP headers
        ip_packet = IP(dst=destination, ttl=ttl)
        udp_packet = UDP(dport=port)

        # Combining the headers
        packet = ip_packet / udp_packet

        # Sending the packet and receive a reply
        reply = sr1(packet, timeout=timeout, verbose=0)

        if reply is None:
            # No reply, print * for timeout
            print(f'{ttl}')
        elif reply.type == 3:
            # Destination reached, print the details
            print(f'{ttl}\t{reply.src}')
            break
        else:
            # Printing the IP address of the intermediate hop
            print(f'{ttl}\t{reply.src}')

        ttl += 1

        if ttl > max_hops:
            break

if __name__ == "__main__":
    dst = "google.co.kr"
    traceroute(dst)