#!/usr/bin/env python3
"""
Network utility tools using Scapy with Terminal UML Visualization
Target: www.google.com (Web)
"""

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
        # 다이어그램에 표시할 노드들 정의
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
        
        uml.add_event(uml.local_ip, dns_server, f"DNS Query: {host}")

        # Send and receive
        response = sr1(dns_query, timeout=timeout, verbose=0)

        if response and response.haslayer(DNS):
            dns_layer = response[DNS]
            uml.add_event(dns_server, uml.local_ip, f"DNS Resp: {dns_layer.ancount} Answers")
            
            print(f"\n>>> Packet Analysis (DNS Response) <<<")
            print(f"Transaction ID: {dns_layer.id} (Hex: {hex(dns_layer.id)})")
            print(f"Flags: QR={dns_layer.qr} (Response), AA={dns_layer.aa} (Authoritative), RD={dns_layer.rd} (Recursion Desired)")
            print(f"Question: {dns_layer.qd.qname.decode('utf-8')} (Type: {dns_layer.qd.qtype})")
            
            if dns_layer.ancount > 0:
                print(f"Answers ({dns_layer.ancount}):")
                for i in range(dns_layer.ancount):
                    answer = dns_layer.an[i]
                    # DNSRR 필드 해석
                    if isinstance(answer, DNSRR):
                        rrname = answer.rrname.decode('utf-8')
                        type_str = "A" if answer.type == 1 else str(answer.type)
                        print(f"  [{i+1}] {rrname} -> {answer.rdata} (Type: {type_str}, TTL: {answer.ttl})")
            else:
                print("No answers found")
        else:
            print("✗ No response (timeout)")
            uml.add_event(dns_server, uml.local_ip, "Timeout")

    except Exception as e:
        print(f"✗ Error: {e}")


def curl_like(target_ip, host_domain, path="/", timeout=5):
    """
    HTTP GET request with HTML content inspection
    """
    print(f"\n[CURL] GET http://{host_domain}{path} (IP: {target_ip})")

    try:
        # Start packet capture in background
        bpf_filter = f"tcp and host {target_ip} and port 80"
        sniffer = AsyncSniffer(filter=bpf_filter, count=15, timeout=5)
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
                # 너무 길면 끊기 (분석용)
                if len(response) > 4096: break
            except socket.timeout:
                break

        sock.close()
        time.sleep(1)  # Wait for packets

        # Stop sniffer
        if sniffer.running:
            sniffer.stop()
        packets = sniffer.results

        # Payload Analysis (HTML Content)
        print(f"\n>>> Packet Analysis (HTTP Content) <<<")
        if response:
            try:
                # 헤더와 바디 분리 시도
                decoded_resp = response.decode('utf-8', errors='ignore')
                headers, _, body = decoded_resp.partition('\r\n\r\n')
                
                print("[HTTP Headers]")
                print('\n'.join(headers.splitlines()[:5])) # 상위 5줄만 출력
                print("...")
                
                print(f"\n[HTTP Body / HTML Content] (Length: {len(body)} bytes)")
                preview = body.strip().replace('\n', ' ')[:200]
                print(f"Content Preview: {preview}...")
            except Exception as e:
                print(f"Could not parse HTTP response: {e}")
        else:
            print("No data received from socket.")

        print(f"\n--- Captured {len(packets)} TCP packets for UML ---")

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
                    if "HTTP/1" in payload: msg = "HTTP Resp"
                
                uml.add_event(src, dst, msg)

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
            
            uml.add_event(uml.local_ip, target_ip, f"ICMP Req seq={i}")

            # Send and receive
            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply:
                rtt = (time.time() - start_time) * 1000
                received += 1
                uml.add_event(target_ip, uml.local_ip, f"ICMP Reply ttl={reply.ttl}")
                
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
                uml.add_event(target_ip, uml.local_ip, "Timeout")
                print(f"Request timeout for icmp_seq={i}")

            sent += 1
            time.sleep(0.5)

    except Exception as e:
        print(f"✗ Error: {e}")


def traceroute_like(target_ip, max_hops=15, timeout=2):
    """
    Traceroute with ICMP Error Message Analysis
    """
    print(f"\n[TRACEROUTE] {target_ip}")

    try:
        for ttl in range(1, max_hops + 1):
            packet = IP(dst=target_ip, ttl=ttl)/ICMP()
            
            uml.add_event(uml.local_ip, target_ip, f"ICMP Req (TTL={ttl})")

            reply = sr1(packet, timeout=timeout, verbose=0)

            if reply is None:
                print(f"{ttl:2d}  * * *")
            else:
                src_ip = reply[IP].src
                print(f"{ttl:2d}  {src_ip}")

                if reply.haslayer(ICMP):
                    icmp_layer = reply[ICMP]
                    
                    if icmp_layer.type == 11: # Time Exceeded
                        uml.add_event(src_ip, uml.local_ip, f"Time Exceeded (TTL={ttl})")
                        
                        # ICMP Time Exceeded 메시지 분석
                        # 보통 ICMP Error 메시지는 원본 패킷의 헤더를 포함함
                        print(f"     >>> Packet Analysis: ICMP Type 11 (Time Exceeded)")
                        if reply.haslayer(IP) and reply[IP].payload:
                            # ICMP payload 안에 있는 내 원본 패킷 정보 확인
                            # 구조: IP(응답) / ICMP(에러) / IP(내꺼) / ICMP(내꺼)
                            inner_layer = reply[IP].payload # ICMP
                            if hasattr(inner_layer, 'payload') and inner_layer.payload:
                                original_ip_layer = inner_layer.payload
                                if isinstance(original_ip_layer, IP):
                                    print(f"     [Original Packet Info inside Error Message]")
                                    print(f"     Src: {original_ip_layer.src} -> Dst: {original_ip_layer.dst}")
                                    print(f"     Original TTL: {original_ip_layer.ttl}")

                    elif icmp_layer.type == 0: # Echo Reply
                        uml.add_event(src_ip, uml.local_ip, "Echo Reply (Reached)")
                        print(f"     >>> Packet Analysis: Destination Reached (Type 0)")
                        print(f"\nReached destination in {ttl} hops")
                        break
    except Exception as e:
        print(f"✗ Error: {e}")


def main():
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

    # 구글 타겟 정의
    WEB_DOMAIN = "www.google.com"
    
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
    uml.draw(title="4. Traceroute Sequence")
    uml.clear()

    print("\n" + "="*60)
    print("All tests completed")
    print("="*60)


if __name__ == "__main__":
    main()