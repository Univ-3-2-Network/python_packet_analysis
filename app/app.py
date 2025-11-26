#!/usr/bin/env python3
"""
Network utility tools using Scapy
Implements: curl, ping, nslookup, traceroute with packet parsing
"""

import sys
import socket
import time
import threading
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR, DNSRR,
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

                        # Parse HTTP status line and headers
                        lines = text.split('\r\n')

                        # Parse status line (HTTP/1.1 200 OK)
                        if lines:
                            status_line = lines[0]
                            parts = status_line.split(' ', 2)
                            if len(parts) >= 3:
                                http_version = parts[0]
                                status_code = parts[1]
                                status_message = parts[2]
                                print(f"Status: {http_version} {status_code} {status_message}")
                            else:
                                print(f"Status: {status_line}")

                        # Parse important headers
                        print(f"\nHeaders:")
                        for line in lines[1:]:
                            if not line:  # Empty line marks end of headers
                                break
                            if ':' in line:
                                header_name, header_value = line.split(':', 1)
                                header_name = header_name.strip()
                                header_value = header_value.strip()
                                # Show important headers
                                if header_name.lower() in ['content-type', 'content-length', 'server', 'date', 'connection', 'transfer-encoding']:
                                    print(f"  {header_name}: {header_value}")

                        # Show packet info
                        print(f"\nPacket Info:")
                        print(f"  {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                        print(f"  TCP Seq={pkt[TCP].seq} Ack={pkt[TCP].ack} Flags=[{pkt[TCP].flags}]")
                        print(f"  Payload size: {len(payload)} bytes")

                        # Show body preview
                        body_start = text.find('\r\n\r\n')
                        if body_start != -1 and body_start + 4 < len(text):
                            body = text[body_start + 4:]
                            print(f"\nBody Preview (first 200 chars):")
                            print(body[:500])

                        http_found = True
                        break
                except:
                    pass

        if not http_found and response:
            print(f"\n--- HTTP Response (from socket) ---")
            text = response.decode('utf-8', errors='ignore')
            lines = text.split('\r\n')

            # Parse status line
            if lines:
                status_line = lines[0]
                parts = status_line.split(' ', 2)
                if len(parts) >= 3:
                    http_version = parts[0]
                    status_code = parts[1]
                    status_message = parts[2]
                    print(f"Status: {http_version} {status_code} {status_message}")
                else:
                    print(f"Status: {status_line}")

            # Parse headers
            print(f"\nHeaders:")
            for line in lines[1:]:
                if not line:
                    break
                if ':' in line:
                    header_name, header_value = line.split(':', 1)
                    header_name = header_name.strip()
                    header_value = header_value.strip()
                    if header_name.lower() in ['content-type', 'content-length', 'server', 'date', 'connection', 'transfer-encoding']:
                        print(f"  {header_name}: {header_value}")

            # Show body preview
            body_start = text.find('\r\n\r\n')
            if body_start != -1 and body_start + 4 < len(text):
                body = text[body_start + 4:]
                print(f"\nBody Preview (first 200 chars):")
                print(body[:200])

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
        # Start packet capture in background
        bpf_filter = f"udp and host {dns_server} and port 53"
        print(f"Starting sniffer with filter: {bpf_filter}")
        sniffer = AsyncSniffer(filter=bpf_filter, prn=None, store=True)
        sniffer.start()

        time.sleep(0.3)  # Let sniffer start

        # Create DNS query using real UDP socket
        import random
        transaction_id = random.randint(1, 65535)

        # Build DNS query packet
        dns_query = DNS(id=transaction_id, rd=1, qd=DNSQR(qname=host))
        query_bytes = bytes(dns_query)

        # Send DNS query via UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query_bytes, (dns_server, 53))
        print(f"✓ DNS query sent (ID: {transaction_id})")

        # Receive DNS response
        try:
            response_data, addr = sock.recvfrom(4096)
            print(f"✓ DNS response received from {addr}")
        except socket.timeout:
            print("✗ Socket timeout - no response received")
            sock.close()
            sniffer.stop()
            return

        sock.close()
        time.sleep(0.3)  # Wait for packets

        # Stop sniffer and analyze packets
        sniffer.stop()
        packets = sniffer.results

        print(f"\n--- Captured {len(packets)} UDP packets ---")

        # Parse captured DNS packets
        for pkt in packets:
            if pkt.haslayer(UDP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                print(f"  {src_ip}:{src_port} -> {dst_ip}:{dst_port} [UDP] Len={pkt[UDP].len}")

        # Parse DNS response
        dns_response = DNS(response_data)

        if dns_response:
            print(f"\n--- DNS Response ---")
            print(f"Transaction ID: {dns_response.id}")
            print(f"Questions: {dns_response.qdcount}")
            print(f"Answers: {dns_response.ancount}")

            # Parse query section
            if dns_response.qd:
                qname = dns_response.qd.qname.decode('utf-8') if isinstance(dns_response.qd.qname, bytes) else str(dns_response.qd.qname)
                print(f"Query: {qname}")

            # Parse answers
            if dns_response.ancount > 0:
                print(f"\nAnswers:")
                # Iterate through answer records properly
                current = dns_response.an
                count = 0
                while current and count < dns_response.ancount:
                    # Check if current has DNS RR attributes (rrname, type, etc.)
                    if not hasattr(current, 'rrname') or not hasattr(current, 'type'):
                        print(f"  [DEBUG] Skipping non-DNSRR layer: {type(current).__name__}")
                        # Try to continue to payload anyway
                        if hasattr(current, 'payload') and current.payload:
                            current = current.payload
                            continue
                        else:
                            break

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

                    count += 1

                    # Move to next record - check payload
                    if hasattr(current, 'payload') and current.payload:
                        next_layer = current.payload
                        # Check if payload has DNSRR attributes (more robust than isinstance)
                        if hasattr(next_layer, 'rrname') or type(next_layer).__name__ == 'DNSRR':
                            current = next_layer
                        else:
                            # Payload exists but is not a DNS RR (likely end of chain)
                            print(f"  [DEBUG] End of DNS chain, payload type: {type(next_layer).__name__}")
                            break
                    else:
                        # No more records
                        break
            else:
                print("No answers found")
        else:
            print("✗ Could not parse DNS response")

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
