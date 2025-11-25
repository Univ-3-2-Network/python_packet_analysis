#!/usr/bin/env python3
"""
Network utility tools using Scapy
Implements: curl, ping, nslookup, traceroute with packet parsing
"""

import socket
import time
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR,
    sr1, send, sniff, conf
)


def curl_like(host, path="/", timeout=5):
    """
    HTTP GET request with packet capture and parsing
    """
    print(f"\n[CURL] GET http://{host}{path}")

    try:
        # Resolve hostname
        dest_ip = socket.gethostbyname(host)
        print(f"Connecting to {dest_ip}:80...")

        # Create HTTP GET request
        http_request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

        # Send SYN packet
        ip = IP(dst=dest_ip)
        syn = TCP(sport=12345, dport=80, flags="S", seq=1000)
        syn_ack = sr1(ip/syn, timeout=timeout, verbose=0)

        if syn_ack and syn_ack.haslayer(TCP):
            print(f"✓ SYN-ACK received from {syn_ack[IP].src}:{syn_ack[TCP].sport}")
            print(f"  Flags: {syn_ack[TCP].flags}, Seq: {syn_ack[TCP].seq}, Ack: {syn_ack[TCP].ack}")

            # Send ACK
            ack = TCP(sport=12345, dport=80, flags="A", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
            send(ip/ack, verbose=0)

            # Send HTTP request
            push = TCP(sport=12345, dport=80, flags="PA", seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1)
            send(ip/push/http_request, verbose=0)
            print(f"✓ HTTP GET request sent")

            # Capture response
            packets = sniff(filter=f"tcp and host {dest_ip} and port 80", count=5, timeout=3)
            for pkt in packets:
                if pkt.haslayer(TCP) and pkt[TCP].flags & 0x18:  # PSH-ACK
                    if pkt.haslayer('Raw'):
                        payload = pkt['Raw'].load.decode('utf-8', errors='ignore')
                        if payload.startswith('HTTP'):
                            print(f"\n--- HTTP Response ---")
                            print(payload[:500])
                            break
        else:
            print("✗ No response (timeout)")

    except Exception as e:
        print(f"✗ Error: {e}")


def ping_like(host, count=4, timeout=2):
    """
    ICMP ping with packet capture and parsing
    """
    print(f"\n[PING] {host}")

    try:
        dest_ip = socket.gethostbyname(host)
        print(f"Pinging {dest_ip} with {count} packets...\n")

        sent = 0
        received = 0

        for i in range(count):
            # Create ICMP echo request
            packet = IP(dst=dest_ip)/ICMP(id=1234, seq=i)
            start_time = time.time()

            # Send and receive
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply:
                rtt = (time.time() - start_time) * 1000
                received += 1
                print(f"Reply from {reply[IP].src}: icmp_seq={i} ttl={reply[IP].ttl} time={rtt:.2f}ms")
                print(f"  ICMP type={reply[ICMP].type} code={reply[ICMP].code}")
            else:
                print(f"Request timeout for icmp_seq={i}")

            sent += 1
            time.sleep(1)

        # Statistics
        loss = ((sent - received) / sent) * 100
        print(f"\n--- Statistics ---")
        print(f"{sent} packets sent, {received} received, {loss:.1f}% packet loss")

    except Exception as e:
        print(f"✗ Error: {e}")


def nslookup_like(host, dns_server="8.8.8.8", timeout=3):
    """
    DNS lookup with packet capture and parsing
    """
    print(f"\n[NSLOOKUP] {host}")
    print(f"Using DNS server: {dns_server}")

    try:
        # Create DNS query
        dns_query = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=host))

        # Send and receive
        response = sr1(dns_query, timeout=timeout, verbose=0)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            print(f"\n--- DNS Response ---")
            print(f"Transaction ID: {dns_layer.id}")
            print(f"Questions: {dns_layer.qdcount}")
            print(f"Answers: {dns_layer.ancount}")

            # Parse answers
            if dns_layer.ancount > 0:
                print(f"\nAnswers:")
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    if hasattr(answer, 'rdata'):
                        print(f"  {answer.rrname.decode('utf-8')} -> {answer.rdata}")
            else:
                print("No answers found")
        else:
            print("✗ No response (timeout)")

    except Exception as e:
        print(f"✗ Error: {e}")


def traceroute_like(host, max_hops=30, timeout=2):
    """
    Traceroute with packet capture and parsing
    """
    print(f"\n[TRACEROUTE] {host}")

    try:
        dest_ip = socket.gethostbyname(host)
        print(f"Tracing route to {dest_ip} (max {max_hops} hops)\n")

        for ttl in range(1, max_hops + 1):
            # Create ICMP packet with specific TTL
            packet = IP(dst=dest_ip, ttl=ttl)/ICMP()
            start_time = time.time()

            # Send and receive
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply is None:
                print(f"{ttl:2d}  * * *")
            else:
                rtt = (time.time() - start_time) * 1000
                hop_ip = reply[IP].src

                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(hop_ip)[0]
                except:
                    hostname = hop_ip

                print(f"{ttl:2d}  {hostname} ({hop_ip})  {rtt:.2f}ms")
                print(f"     ICMP type={reply[ICMP].type} code={reply[ICMP].code}")

                # Check if reached destination
                if reply[IP].src == dest_ip and reply[ICMP].type == 0:
                    print(f"\nReached destination in {ttl} hops")
                    break

    except Exception as e:
        print(f"✗ Error: {e}")


def main():
    """
    Main function to run all network utilities
    """
    print("="*60)
    print("Network Utility Tools (Scapy)")
    print("="*60)

    # Disable scapy verbose output
    conf.verb = 0

    target = "example.com"

    # Run all utilities
    curl_like(target, "/")
    ping_like(target, count=4)
    nslookup_like(target)
    traceroute_like(target, max_hops=15)

    print("\n" + "="*60)
    print("All tests completed")
    print("="*60)


if __name__ == "__main__":
    main()
