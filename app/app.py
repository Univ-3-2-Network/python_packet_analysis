#!/usr/bin/env python3
"""
Network utility tools using Scapy with Terminal UML Visualization
Target: www.google.com (Web)
"""

import sys
import socket
import time
import os
import sys
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR, DNSRR, Raw,
    sr1, AsyncSniffer, conf
)

# ==========================================
# Terminal UML Drawing Class
# ==========================================
class TerminalUML:
    def __init__(self):
        self.events = []
        # 다이어그램에 표시할 노드들 정의 (Linux 제거)
        self.nodes = ["Client", "DNS", "Router", "Web"]
        self.node_positions = {name: i * 20 for i, name in enumerate(self.nodes)}
        
        # IP 주소와 노드 이름 매핑
        self.ip_map = {
            "127.0.0.1": "Client",
            "8.8.8.8": "DNS",
            # Web IP는 main에서 동적으로 추가됨
        }
        # 로컬 IP 확인하여 매핑에 추가
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            self.ip_map[self.local_ip] = "Client"
            s.close()
        except:
            self.local_ip = "127.0.0.1"

    def get_node_name(self, ip):
        # IP가 매핑되어 있으면 이름 반환, 아니면 Router로 취급
        return self.ip_map.get(ip, "Router")

    def add_event(self, src_ip, dst_ip, description, color_code=None):
        src = self.get_node_name(src_ip)
        dst = self.get_node_name(dst_ip)
        self.events.append((src, dst, description))
    
    def clear(self):
        """이벤트 목록 초기화 (다음 다이어그램을 위해)"""
        self.events = []


    def draw(self, title="Sequence Diagram"):
        print("\n" + "="*80)
        print(f"ASCII Visualization: {title}")
        print("="*80 + "\n")

        if not self.events:
            print("No events captured.")
            print("="*80)
            return

        
        # 1. 헤더 출력
        header = ""
        for node in self.nodes:
            header += f"{node:^20}"
        print(header)
        print("-" * len(header))

        # 2. 파이프라인(기둥) 및 화살표 그리기
        for src, dst, desc in self.events:
            if src == dst: continue

            try:
                src_idx = self.nodes.index(src)
                dst_idx = self.nodes.index(dst)
            except ValueError:
                continue # 알 수 없는 노드는 건너뜀
            
            # 기둥 그리기
            line_buffer = ""
            for i in range(len(self.nodes)):
                prefix = " " * 9
                suffix = " " * 10
                char = "|"
                if i == src_idx: char = "o"
                elif i == dst_idx: char = "*"
                line_buffer += f"{prefix}{char}{suffix}"
            
            # 1. 메시지 출력 (화살표 위)
            print(line_buffer) 
            
            # 2. 화살표 가시화
            left, right = min(src_idx, dst_idx), max(src_idx, dst_idx)
            start_pos = left * 20 + 10
            end_pos = right * 20 + 10
            dist = end_pos - start_pos
            
            arrow_line = " " * start_pos
            if src_idx < dst_idx:
                arrow_line += "-" * (dist - 1) + "> " + desc
            else:
                arrow_line += "<" + "-" * (dist - 1) + " " + desc
            
            print(arrow_line)

        print("-" * len(header))
        print("="*80)


# 전역 UML 객체
uml = TerminalUML()


# ==========================================
# Network Functions
# ==========================================

def nslookup_like(host, dns_server="8.8.8.8", timeout=3):
    """
    DNS lookup with packet content analysis
    """
    print(f"\n[NSLOOKUP] {host}")
    print(f"Using DNS server: {dns_server}")

    try:
        # Create DNS query
        dns_query = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=host))

        uml.add_event(uml.local_ip, dns_server, f"DNS Query :53 [{host}]")

        # Send and receive
        response = sr1(dns_query, timeout=timeout, verbose=0)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            uml.add_event(dns_server, uml.local_ip, f"DNS Resp :53 [{dns_layer.ancount} ans]")
            
            print(f"\n--- DNS Response ---")
            print(f"Transaction ID: {dns_layer.id}")
            print(f"Flags: QR={dns_layer.qr} (Response), AA={dns_layer.aa} (Authoritative), RD={dns_layer.rd} (Recursion Desired)")
            print(f"Question: {dns_layer.qd.qname.decode('utf-8')} (Type: {dns_layer.qd.qtype})")
            
            if dns_layer.ancount > 0:
                print(f"Answers ({dns_layer.ancount} records):")

                # Robust multiple answer parsing using payload chain
                current = dns_layer.an
                count = 0
                while current and count < dns_layer.ancount:
                    # Check if current layer has DNS RR attributes
                    if not hasattr(current, 'rrname') or not hasattr(current, 'type'):
                        # Skip non-DNSRR layers
                        if hasattr(current, 'payload') and current.payload:
                            current = current.payload
                            continue
                        else:
                            break

                    # Parse DNS record
                    rrname = current.rrname.decode('utf-8') if isinstance(current.rrname, bytes) else str(current.rrname)

                    # Get record data
                    if hasattr(current, 'rdata'):
                        rdata = current.rdata
                    elif hasattr(current, 'address'):
                        rdata = current.address
                    else:
                        rdata = "N/A"

                    # Get type name
                    type_names = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX', 28: 'AAAA'}
                    type_str = type_names.get(current.type, str(current.type))
                    ttl = current.ttl if hasattr(current, 'ttl') else 0

                    print(f"  [{count+1}] {rrname} -> {rdata} (Type: {type_str}, TTL: {ttl}s)")
                    count += 1

                    # Move to next record via payload chain
                    if hasattr(current, 'payload') and current.payload:
                        next_layer = current.payload
                        if hasattr(next_layer, 'rrname') or type(next_layer).__name__ == 'DNSRR':
                            current = next_layer
                        else:
                            break
                    else:
                        break
            else:
                print("No answers found")
        else:
            print("✗ No response (timeout)")
            uml.add_event(dns_server, uml.local_ip, "DNS Timeout [no reply]")

    except Exception as e:
        print(f"✗ Error: {e}")


def curl_like(target_ip, host_domain, path="/", timeout=5):
    """
    HTTP GET request
    """
    print(f"\n[CURL] GET http://{host_domain}{path} (IP: {target_ip})")

    try:
        # Start packet capture in background
        bpf_filter = f"tcp and host {target_ip} and port 80"
        sniffer = AsyncSniffer(filter=bpf_filter, count=10, timeout=5)
        sniffer.start()

        time.sleep(0.5)  # Let sniffer start

        # Create HTTP GET request using real socket
        http_request = f"GET {path} HTTP/1.1\r\nHost: {host_domain}\r\nConnection: close\r\n\r\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target_ip, 80))
        sock.sendall(http_request.encode('utf-8'))

        print(f"✓ HTTP GET request sent")

        # Receive response
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk: break
                response += chunk
                if len(response) > 1024: break
            except socket.timeout:
                break

        sock.close()
        time.sleep(1)  # Wait for packets

        # Stop sniffer
        if sniffer.running:
            sniffer.stop()
        packets = sniffer.results

        print(f"\n--- Captured {len(packets)} TCP packets ---")
        print(f"{'#':<3} {'Direction':<40} {'Flags':<10} {'Seq':<12} {'Ack':<12} {'Description':<30}")
        print("-" * 110)

        # Parse packets for UML and Display
        pkt_num = 0
        for pkt in packets:
            if pkt.haslayer(TCP):
                pkt_num += 1
                src = pkt[IP].src
                dst = pkt[IP].dst
                flags = pkt[TCP].flags
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                seq = pkt[TCP].seq
                ack = pkt[TCP].ack

                # Determine direction and role
                direction = f"{src}:{sport} -> {dst}:{dport}"

                # Parse TCP flags into readable format
                flag_str = str(flags)
                flag_names = []
                if 'S' in flag_str: flag_names.append("SYN")
                if 'A' in flag_str: flag_names.append("ACK")
                if 'F' in flag_str: flag_names.append("FIN")
                if 'P' in flag_str: flag_names.append("PSH")
                if 'R' in flag_str: flag_names.append("RST")
                if 'U' in flag_str: flag_names.append("URG")
                flag_display = "+".join(flag_names) if flag_names else str(flags)

                # Determine packet description
                description = ""
                if pkt.haslayer('Raw'):
                    payload = bytes(pkt['Raw'].load).decode('utf-8', errors='ignore')
                    if "GET" in payload:
                        description = "HTTP GET Request"
                    elif "HTTP/1" in payload:
                        description = "HTTP Response"
                    else:
                        description = "Data"
                else:
                    if 'S' in flag_str and 'A' not in flag_str:
                        description = "TCP Handshake (1/3)"
                    elif 'S' in flag_str and 'A' in flag_str:
                        description = "TCP Handshake (2/3)"
                    elif 'A' in flag_str and 'S' not in flag_str and 'F' not in flag_str:
                        description = "TCP Handshake (3/3)" if pkt_num == 3 else "ACK"
                    elif 'F' in flag_str:
                        description = "Connection Close"

                # Console Print - per line with details
                print(f"{pkt_num:<3} {direction:<40} {flag_display:<10} {seq:<12} {ack:<12} {description:<30}")

                # UML Logging with detailed flags
                if pkt.haslayer('Raw'):
                    payload = bytes(pkt['Raw'].load).decode('utf-8', errors='ignore')
                    if "GET" in payload:
                        msg = f"HTTP GET :{dport} [PSH+ACK]"
                    elif "HTTP/1" in payload:
                        msg = f"HTTP 200 :{sport} [PSH+ACK]"
                    else:
                        msg = f"TCP :{dport} [{flag_display}]"
                else:
                    msg = f"TCP :{dport} [{flag_display}]"

                uml.add_event(src, dst, msg)

        # Print HTTP Response Payload text
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

    except Exception as e:
        print(f"✗ Error: {e}")


def ping_like(target_ip, count=2, timeout=2):
    """
    ICMP ping with payload inspection
    """
    print(f"\n[PING] {target_ip}")

    try:
        sent = 0
        received = 0

        # 식별 가능한 커스텀 데이터 삽입
        custom_payload = "HelloPing"

        for i in range(count):
            # Create ICMP echo request with payload
            packet = IP(dst=target_ip)/ICMP(id=1234, seq=i)/Raw(load=custom_payload)
            start_time = time.time()

            uml.add_event(uml.local_ip, target_ip, f"ICMP Echo Req [seq={i}]")

            # Send and receive
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply:
                rtt = (time.time() - start_time) * 1000
                received += 1
                uml.add_event(target_ip, uml.local_ip, f"ICMP Echo Reply [ttl={reply.ttl}]")
                
                print(f"Reply from {reply[IP].src}: icmp_seq={i} ttl={reply[IP].ttl} time={rtt:.2f}ms")
                
                # Payload 확인
                if reply.haslayer(Raw):
                    received_load = reply[Raw].load.decode('utf-8', errors='ignore')
                    print(f"  >>> Packet Analysis: Received Payload='{received_load}'")
                    if received_load == custom_payload:
                        print("  >>> (Integrity Check: MATCH - Data returned correctly)")
                    else:
                        print("  >>> (Integrity Check: MISMATCH)")
            else:
                uml.add_event(target_ip, uml.local_ip, f"ICMP Timeout [seq={i}]")
                print(f"Request timeout for icmp_seq={i}")

            sent += 1
            time.sleep(0.5)

    except Exception as e:
        print(f"✗ Error: {e}")


def traceroute_like(target_ip, max_hops=15, timeout=2):
    """
    Traceroute using UDP packets (like Linux traceroute)
    More reliable in Docker/NAT environments than ICMP
    """
    print(f"\n[TRACEROUTE] {target_ip}")
    print(f"Tracing route with UDP packets (max {max_hops} hops)...")
    print(f"Each packet goes to SAME destination but with DIFFERENT TTL values\n")

    try:
        dest_port = 33434  # Standard traceroute starting port
        reached = False

        for ttl in range(1, max_hops + 1):
            # KEY POINT: All packets go to same destination (target_ip)
            # But each has different TTL - routers along path send back ICMP errors
            current_port = dest_port + ttl
            packet = IP(dst=target_ip, ttl=ttl)/UDP(dport=current_port)

            start_time = time.time()

            uml.add_event(uml.local_ip, "Router", f"UDP :{current_port} [TTL={ttl}]")

            # Send packet and wait for ICMP Time Exceeded or Port Unreachable
            reply = sr1(packet, timeout=timeout, verbose=0)

            rtt = (time.time() - start_time) * 1000

            if reply is None:
                print(f"{ttl:2d}  * * * (Request timeout)")
            else:
                src_ip = reply[IP].src

                # Try to resolve hostname
                try:
                    hostname = socket.gethostbyaddr(src_ip)[0]
                    display_name = f"{hostname}"
                except:
                    display_name = src_ip

                print(f"{ttl:2d}  {display_name} ({src_ip})  {rtt:.2f}ms", end="")

                # Analyze ICMP response
                if reply.haslayer(ICMP):
                    icmp_layer = reply[ICMP]
                    icmp_type = icmp_layer.type
                    icmp_code = icmp_layer.code

                    if icmp_type == 11:  # Time Exceeded
                        print(f"  [ICMP Type 11: TTL Exceeded]")
                        uml.add_event(src_ip, uml.local_ip, f"ICMP Time Exceeded [TTL={ttl}]")

                        # Analyze original packet inside ICMP error message
                        print(f"     >>> Packet Analysis:")
                        if hasattr(icmp_layer, 'payload') and icmp_layer.payload:
                            original_ip = icmp_layer.payload
                            if isinstance(original_ip, IP):
                                print(f"     [Original Packet] Src: {original_ip.src} -> Dst: {original_ip.dst}, TTL: {original_ip.ttl}")
                                if original_ip.haslayer(UDP):
                                    print(f"     [Original UDP] Port: {original_ip[UDP].dport}")

                    elif icmp_type == 3:  # Destination Unreachable
                        if icmp_code == 3:  # Port Unreachable = destination reached!
                            print(f"  [ICMP Type 3 Code 3: Port Unreachable - DESTINATION REACHED!]")
                            uml.add_event(src_ip, uml.local_ip, f"ICMP Port Unreach :{current_port} [OK!]")
                            print(f"     >>> This means we successfully reached the destination server!")
                            print(f"\n✓ Reached destination in {ttl} hops")
                            reached = True
                            break
                        else:
                            print(f"  [ICMP Type 3 Code {icmp_code}: Dest Unreachable]")
                            uml.add_event(src_ip, uml.local_ip, f"ICMP Dest Unreach [code={icmp_code}]")

                    elif icmp_type == 0:  # Echo Reply (if ICMP was used instead)
                        print(f"  [ICMP Type 0: Echo Reply - DESTINATION REACHED!]")
                        uml.add_event(src_ip, uml.local_ip, "ICMP Echo Reply [Reached]")
                        print(f"\n✓ Reached destination in {ttl} hops")
                        reached = True
                        break
                    else:
                        print(f"  [ICMP Type {icmp_type} Code {icmp_code}]")
                        uml.add_event(src_ip, uml.local_ip, f"ICMP Type={icmp_type}/Code={icmp_code}")
                else:
                    print(f"  [Non-ICMP response]")
                    uml.add_event(src_ip, uml.local_ip, f"Response [TTL={ttl}]")

        if not reached:
            print(f"\n⚠ Did not reach destination within {max_hops} hops")
            print(f"   (This is normal - some servers don't respond to traceroute)")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # set WEB_DOMAIN from ARG
    if len(sys.argv) > 1:
        WEB_DOMAIN = sys.argv[1]
    else:
        WEB_DOMAIN = "google.co.kr"
    
    # 0. 관리자 권한 체크 및 자동 재실행
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("[알림] 관리자 권한(Root)이 필요합니다.")
        print("비밀번호를 입력하면 자동으로 sudo 권한으로 재실행합니다...")
        print("="*60 + "\n")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[오류] 재실행 실패: {e}")
            sys.exit(1)

    print("="*60)
    print(f"Network Utility Tools (Scapy) - Target: {WEB_DOMAIN}")
    print("="*60)

    # Disable scapy verbose output
    conf.verb = 0

    # 도메인 IP 동적 확인 (Resolve)
    try:
        WEB_IP = socket.gethostbyname(WEB_DOMAIN)
        print(f"[*] Resolved {WEB_DOMAIN} to {WEB_IP}")
    except socket.gaierror:
        print(f"[!] {WEB_DOMAIN}의 IP를 찾을 수 없습니다. 인터넷 연결을 확인하세요.")
        sys.exit(1)

    # UML 객체에 Web IP 등록 (동적 매핑)
    uml.ip_map[WEB_IP] = "Web"

    # [수정됨] 각 도구 실행 후 즉시 다이어그램 그리기 및 초기화

    # 1. NSLookup
    nslookup_like(WEB_DOMAIN)
    uml.draw(title="1. NSLookup Sequence")
    uml.clear()

    # 2. Curl
    curl_like(WEB_IP, WEB_DOMAIN)
    uml.draw(title="2. Curl (HTTP/TCP) Sequence")
    uml.clear()

    # 3. Ping
    ping_like(WEB_IP, count=4)
    uml.draw(title="3. Ping (ICMP) Sequence")
    uml.clear()
    
    # 4. Traceroute
    traceroute_like(WEB_IP, max_hops=15)
    uml.draw(title="4. Traceroute (ICMP/UDP) Sequence")
    uml.clear()

    print("\n" + "="*60)
    print("All tests completed")
    print("="*60)
