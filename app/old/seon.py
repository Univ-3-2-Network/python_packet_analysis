#!/usr/bin/env python3
"""
Network utility tools using Scapy
Implements: curl, ping, nslookup, traceroute with packet parsing
"""

import socket
import time
import threading
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR,
    sr1, send, sniff, conf, AsyncSniffer
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

        # Start packet capture in background
        bpf_filter = f"tcp and host {dest_ip} and port 80"
        sniffer = AsyncSniffer(filter=bpf_filter, prn=None, store=True)
        sniffer.start()

        time.sleep(0.5)  # Let sniffer start

        # Create HTTP GET request using real socket
        http_request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((dest_ip, 80))
        sock.sendall(http_request.encode('utf-8'))

        print(f"✓ HTTP GET request sent")

        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 1024:  # Get first 1KB
                    break
            except socket.timeout:
                break

        sock.close()
        time.sleep(0.5)  # Wait for packets

        # Stop sniffer and analyze packets
        sniffer.stop()
        packets = sniffer.results

        print(f"\n--- Captured {len(packets)} TCP packets ---")

        # Parse TCP handshake
        for pkt in packets[:3]:
            if pkt.haslayer(TCP):
                tcp_flags = pkt[TCP].flags
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport

                flag_str = str(tcp_flags)
                print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flag_str}] Seq={pkt[TCP].seq} Ack={pkt[TCP].ack}")

        # Parse HTTP response payload
        http_found = False
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer('Raw'):
                payload = pkt['Raw'].load
                try:
                    text = payload.decode('utf-8', errors='ignore')
                    if text.startswith('HTTP'):
                        print(f"\n--- HTTP Response (from packet) ---")
                        print(text[:500])
                        http_found = True
                        break
                except:
                    pass

        if not http_found and response:
            print(f"\n--- HTTP Response (from socket) ---")
            print(response.decode('utf-8', errors='ignore')[:500])

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
        dns_query = IP(dst=dns_server)/UDP(dport=53, sport=54321)/DNS(rd=1, qd=DNSQR(qname=host))

        # Send and receive
        response = sr1(dns_query, timeout=timeout, verbose=0)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            print(f"\n--- DNS Response ---")
            print(f"Transaction ID: {dns_layer.id}")
            print(f"Questions: {dns_layer.qdcount}")
            print(f"Answers: {dns_layer.ancount}")

            # Parse query section
            if dns_layer.qd:
                qname = dns_layer.qd.qname.decode('utf-8') if isinstance(dns_layer.qd.qname, bytes) else str(dns_layer.qd.qname)
                print(f"Query: {qname}")

            # Parse answers
            if dns_layer.ancount > 0:
                print(f"\nAnswers:")
                # Iterate through answer records properly
                current = dns_layer.an
                count = 0
                while current and count < dns_layer.ancount:
                    # Get record name
                    try:
                        rrname = current.rrname.decode('utf-8') if isinstance(current.rrname, bytes) else str(current.rrname)
                    except:
                        rrname = str(current.rrname)

                    # Get record data based on type
                    if hasattr(current, 'rdata'):
                        rdata = current.rdata
                    elif hasattr(current, 'address'):  # A record
                        rdata = current.address
                    elif hasattr(current, 'exchange'):  # MX record
                        rdata = current.exchange
                    elif hasattr(current, 'target'):  # SRV/CNAME record
                        rdata = current.target
                    else:
                        rdata = "N/A"

                    # Get record type
                    rtype = current.type if hasattr(current, 'type') else 1
                    type_names = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 28: 'AAAA'}
                    type_str = type_names.get(rtype, str(rtype))

                    print(f"  [{type_str}] {rrname} -> {rdata}")

                    # Move to next record
                    current = current.payload if hasattr(current, 'payload') else None
                    count += 1
            else:
                print("No answers found")
        else:
            print("✗ No response (timeout)")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()


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


if __name__ == "__main__":
    import sys

    conf.verb = 0

    if len(sys.argv) > 1:
        target_host = sys.argv[1]
    else:
        target_host = "www.google.com"

    print(f"\n{'='*60}")
    print(f"Network Utility Tools (Scapy)")
    print(f"Target Host: {target_host}")
    print(f"{'='*60}")

    try:
        nslookup_like(target_host)
        ping_like(target_host, count = 4)
        traceroute_like(target_host, max_hops=15)
        curl_like(target_host)

        print(f"\n{'='*60}")
        print("All tests completed")
        print(f"{'='*60}")

    except KeyboardInterrupt:
        print("\nProgram Interrupted.")
