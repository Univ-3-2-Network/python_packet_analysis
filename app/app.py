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
    IP, TCP, ICMP, UDP, DNS, DNSQR,
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

    def draw(self):
        print("\n" + "="*80)
        print("Network Sequence Diagram (ASCII Visualization)")
        print("="*80 + "\n")

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
    DNS lookup
    """
    print(f"\n[NSLOOKUP] {host}")
    print(f"Using DNS server: {dns_server}")

    try:
        # Create DNS query
        dns_query = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=host))
        
        uml.add_event(uml.local_ip, dns_server, f"DNS Query: {host}")

        # Send and receive
        response = sr1(dns_query, timeout=timeout, verbose=0)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            uml.add_event(dns_server, uml.local_ip, f"DNS Resp: {dns_layer.ancount} Answers")
            
            print(f"\n--- DNS Response ---")
            print(f"Transaction ID: {dns_layer.id}")
            
            if dns_layer.ancount > 0:
                print(f"Answers:")
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    if hasattr(answer, 'rdata'):
                        print(f"  {answer.rrname.decode('utf-8')} -> {answer.rdata}")
            else:
                print("No answers found")
        else:
            print("✗ No response (timeout)")
            uml.add_event(dns_server, uml.local_ip, "Timeout")

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

        # Parse packets for UML and Display
        for pkt in packets:
            if pkt.haslayer(TCP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                flags = pkt[TCP].flags
                
                # UML Logging
                msg = f"TCP [{flags}]"
                if pkt.haslayer('Raw'):
                    payload = bytes(pkt['Raw'].load).decode('utf-8', errors='ignore')
                    if "GET" in payload: msg = "HTTP GET"
                    if "HTTP/1" in payload: msg = "HTTP 200 OK"
                
                uml.add_event(src, dst, msg)

                # Console Print
                print(f"  {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport} [{flags}]")

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


def ping_like(target_ip, count=4, timeout=2):
    """
    ICMP ping
    """
    print(f"\n[PING] {target_ip}")

    try:
        sent = 0
        received = 0

        for i in range(count):
            # Create ICMP echo request
            packet = IP(dst=target_ip)/ICMP(id=1234, seq=i)
            start_time = time.time()
            
            uml.add_event(uml.local_ip, target_ip, f"ICMP Request seq={i}")

            # Send and receive
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply:
                rtt = (time.time() - start_time) * 1000
                received += 1
                uml.add_event(target_ip, uml.local_ip, f"ICMP Reply ttl={reply.ttl}")
                print(f"Reply from {reply[IP].src}: icmp_seq={i} ttl={reply[IP].ttl} time={rtt:.2f}ms")
            else:
                uml.add_event(target_ip, uml.local_ip, "Timeout")
                print(f"Request timeout for icmp_seq={i}")

            sent += 1
            time.sleep(0.5)

    except Exception as e:
        print(f"✗ Error: {e}")


def traceroute_like(target_ip, max_hops=15, timeout=2):
    """
    Traceroute
    """
    print(f"\n[TRACEROUTE] {target_ip}")

    try:
        for ttl in range(1, max_hops + 1):
            packet = IP(dst=target_ip, ttl=ttl)/ICMP()

            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply is None:
                print(f"{ttl:2d}  * * *")
            else:
                src_ip = reply[IP].src
                print(f"{ttl:2d}  {src_ip}")

                if reply.haslayer(ICMP):
                    if reply[ICMP].type == 11: # Time Exceeded
                        uml.add_event(src_ip, uml.local_ip, f"ICMP Time Exceeded (TTL={ttl})")
                    elif reply[ICMP].type == 0: # Echo Reply
                        uml.add_event(src_ip, uml.local_ip, "ICMP Echo Reply (Reached)")
                        print(f"\nReached destination in {ttl} hops")
                        break
    except Exception as e:
        print(f"✗ Error: {e}")


if __name__ == "__main__":
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
    print("Network Utility Tools (Scapy) - Target: Google")
    print("="*60)

    # Disable scapy verbose output
    conf.verb = 0

    # set WEB_DOMAIN from ARG
    if len(sys.argv) > 1:
        WEB_DOMAIN = sys.argv[1]
    else:
        WEB_DOMAIN = "google.co.kr"
    
    # 도메인 IP 동적 확인 (Resolve)
    try:
        WEB_IP = socket.gethostbyname(WEB_DOMAIN)
        print(f"[*] Resolved {WEB_DOMAIN} to {WEB_IP}")
    except socket.gaierror:
        print(f"[!] {WEB_DOMAIN}의 IP를 찾을 수 없습니다. 인터넷 연결을 확인하세요.")
        sys.exit(1)

    # UML 객체에 Web IP 등록 (동적 매핑)
    uml.ip_map[WEB_IP] = "Web"

    # Run all utilities
    nslookup_like(WEB_DOMAIN)
    curl_like(WEB_IP, WEB_DOMAIN)
    ping_like(WEB_IP, count=4)
    
    # Traceroute도 구글 서버를 대상으로 수행
    traceroute_like(WEB_IP, max_hops=15)

    # 마지막에 UML 출력
    uml.draw()

    print("\n" + "="*60)
    print("All tests completed")
    print("="*60)
