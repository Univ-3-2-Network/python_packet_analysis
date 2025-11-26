import socket
import time
import os
import sys
from scapy.all import (
    IP, TCP, ICMP, UDP, DNS, DNSQR,
    sr1, AsyncSniffer, conf
)

# PlantUML 생성을 위한 클래스
class PlantUMLLogger:
    def __init__(self, filename="network_sequence.puml"):
        self.filename = filename
        self.lines = []
        self._init_diagram()

    def _init_diagram(self):
        self.lines.append("@startuml")
        self.lines.append("skinparam sequenceMessageAlign center")
        self.lines.append("actor User")
        self.lines.append('participant "Local Client" as Client')
        self.lines.append('participant "DNS Server" as DNS')
        self.lines.append('participant "Web Server\n(www.tukorea.ac.kr)" as Web')
        self.lines.append('participant "Linux Server\n(linux.tukorea.ac.kr)" as Linux')
        self.lines.append('participant "Routers/Gateways" as Net')
        self.lines.append("")

    def add_note(self, participant, note):
        self.lines.append(f"note right of {participant}: {note}")

    def add_flow(self, src, dst, msg, color=None):
        # 매핑: IP나 이름을 다이어그램 참여자(Participant) 별명으로 변환
        src_name = self._map_name(src)
        dst_name = self._map_name(dst)
        
        arrow = "->"
        if color:
            arrow = f"-[# {color}]->"
        
        self.lines.append(f'{src_name} {arrow} {dst_name} : {msg}')

    def _map_name(self, name):
        # 단순화를 위해 IP나 키워드를 다이어그램 ID로 매핑
        name_lower = str(name).lower()
        if "client" in name_lower or "127.0.0.1" in name_lower:
            return "Client"
        if "8.8.8.8" in name_lower or "dns" in name_lower:
            return "DNS"
        if "210.93.48.196" in name_lower or "www" in name_lower:
            return "Web"
        if "210.93.57.50" in name_lower or "linux" in name_lower:
            return "Linux"
        return "Net" # 그 외는 라우터/게이트웨이로 처리

    def add_divider(self, title):
        self.lines.append(f"== {title} ==")

    def save(self):
        self.lines.append("@enduml")
        repo_root = os.path.dirname(os.path.abspath(__file__))
        filepath = os.path.join(repo_root, self.filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(self.lines))
        print(f"\n[Graph Generated] File saved to: {filepath}")

# 전역 로거 생성
uml = PlantUMLLogger()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

LOCAL_IP = get_local_ip()

def nslookup_scapy(domain, dns_server="8.8.8.8"):
    print(f"\n[NSLOOKUP] Querying {domain} via {dns_server}")
    uml.add_divider(f"NSLookup: {domain}")
    
    try:
        # DNS Query
        dns_req = IP(dst=dns_server)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
        uml.add_flow("Client", "DNS", f"DNS Query (A) {domain}", "blue")
        
        response = sr1(dns_req, verbose=0, timeout=2)
        
        if response and response.haslayer(DNS):
            # DNS Response parsing
            ans_count = response[DNS].ancount
            summary = f"DNS Resp: {ans_count} Answers"
            uml.add_flow("DNS", "Client", summary, "blue")
            
            for i in range(ans_count):
                rr = response[DNS].an[i]
                if hasattr(rr, 'rdata'):
                    print(f"  Result: {rr.rdata}")
                    uml.add_note("Client", f"Resolved IP: {rr.rdata}")
        else:
            uml.add_flow("DNS", "Client", "Timeout / No Response", "red")
            
    except Exception as e:
        print(f"Error: {e}")

def curl_scapy(target_ip, host_domain):
    print(f"\n[CURL] HTTP GET to {host_domain} ({target_ip})")
    uml.add_divider(f"Curl (HTTP): {host_domain}")
    
    # 패킷 캡처 시작 (비동기)
    # 내 IP와 목적지 IP 사이의 TCP 패킷만 캡처
    bpf_filter = f"tcp and host {target_ip} and port 80"
    sniffer = AsyncSniffer(filter=bpf_filter, count=10, timeout=5) # 최대 10개만 캡처 (핸드셰이크 + HTTP)
    sniffer.start()
    time.sleep(0.5)

    try:
        # 실제 소켓으로 요청 전송
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        
        # 1. Connect (3-way handshake 발생)
        s.connect((target_ip, 80))
        
        # 2. Send HTTP Request
        req = f"GET / HTTP/1.1\r\nHost: {host_domain}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        
        # 3. Receive Response
        resp = s.recv(1024)
        s.close()
    except Exception as e:
        print(f"Connection failed: {e}")

    time.sleep(1) # 패킷 캡처 대기
    # 스니퍼가 정상적으로 시작되지 않았을 경우 stop()에서 오류가 발생할 수 있음
    try:
        if sniffer.running:
            sniffer.stop()
    except Exception:
        pass
        
    packets = sniffer.results

    # 캡처된 패킷 분석하여 다이어그램 그리기
    handshake_done = False
    for pkt in packets:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # Scapy Flags는 FlagValue 객체이므로 문자열로 변환하여 확인
            flags_str = str(flags)
            
            msg = f"TCP [{flags_str}] Seq={pkt[TCP].seq}"
            
            if src == LOCAL_IP:
                source_node = "Client"
                dest_node = "Web"
                color = "green"
            else:
                source_node = "Web"
                dest_node = "Client"
                color = "orange"

            # 데이터가 있는 경우 (HTTP 메시지)
            if pkt.haslayer("Raw"):
                try:
                    payload = pkt["Raw"].load.decode(errors='ignore')
                    if "GET /" in payload:
                        msg = "HTTP GET /"
                        color = "blue"
                    elif "HTTP/1." in payload:
                        status = payload.split('\r\n')[0]
                        msg = f"HTTP Resp: {status}"
                        color = "blue"
                except:
                    pass
            
            uml.add_flow(source_node, dest_node, msg, color)

def ping_scapy(target_ip):
    print(f"\n[PING] Pinging {target_ip}")
    uml.add_divider(f"Ping: {target_ip}")
    
    for i in range(2): # 2번만 수행
        pkt = IP(dst=target_ip)/ICMP(id=1000, seq=i)
        uml.add_flow("Client", "Web", f"ICMP Echo Request (seq={i})", "black")
        
        rep = sr1(pkt, verbose=0, timeout=1)
        
        if rep:
            uml.add_flow("Web", "Client", f"ICMP Echo Reply (ttl={rep.ttl})", "black")
            print(f"  Reply from {rep.src}: time=xx ms")
        else:
            uml.add_flow("Web", "Client", "Timeout", "red")
            print("  Request timed out")
        time.sleep(0.5)

def traceroute_scapy(target_ip, max_hops=12):
    print(f"\n[TRACEROUTE] Tracing to {target_ip} (Linux Server)")
    uml.add_divider(f"Traceroute: {target_ip}")
    
    for ttl in range(1, max_hops + 1):
        pkt = IP(dst=target_ip, ttl=ttl)/ICMP()
        
        # 다이어그램 단순화를 위해 모든 요청을 그리진 않고, 중요 이벤트만 기록
        # uml.add_flow("Client", "Net", f"ICMP Request (TTL={ttl})", "gray")
        
        rep = sr1(pkt, verbose=0, timeout=2)
        
        if rep is None:
            print(f"{ttl}: *")
            # uml.add_flow("Net", "Client", "Timeout", "red")
        else:
            src_ip = rep.src
            print(f"{ttl}: {src_ip}")
            
            if rep.haslayer(ICMP):
                type_code = rep[ICMP].type
                if type_code == 11: # Time Exceeded
                    uml.add_flow("Client", "Net", f"TTL={ttl} Exceeded at {src_ip}", "gray")
                    uml.add_flow("Net", "Client", f"ICMP Time Exceeded ({src_ip})", "purple")
                elif type_code == 0: # Echo Reply (도착)
                    uml.add_flow("Client", "Linux", f"TTL={ttl} Reached Target", "green")
                    uml.add_flow("Linux", "Client", "ICMP Echo Reply (Destination Reached)", "green")
                    break
                elif type_code == 3: # Destination Unreachable
                    uml.add_flow("Net", "Client", f"Dest Unreachable from {src_ip}", "red")
                    break

if __name__ == "__main__":
    # 0. 관리자 권한 체크 및 자동 재실행
    # os.geteuid()가 0이 아니면(일반 유저면) sudo를 붙여서 재실행합니다.
    if os.geteuid() != 0:
        print("\n" + "="*60)
        print("[알림] 관리자 권한(Root)이 필요합니다.")
        print("비밀번호를 입력하면 자동으로 sudo 권한으로 재실행합니다...")
        print("="*60 + "\n")
        try:
            # os.execvp는 현재 프로세스를 새로운 프로세스(sudo)로 대체합니다.
            # 실행 명령어: sudo python3 [현재파일] [인자들...]
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[오류] 재실행 실패: {e}")
            sys.exit(1)

    # Scapy 설정 (출력 최소화)
    conf.verb = 0
    
    # 1. NSLookup (www.tukorea.ac.kr)
    # 실제 IP를 얻기 위해 먼저 수행
    nslookup_scapy("www.google.com")  # 구글 DNS로 테스트
    
    # 2. Curl (Web Server)
    # 학교 웹서버 IP: 210.93.48.196
    curl_scapy("142.250.206.196","www.google.com")
    
    # 3. Ping (Web Server)
    ping_scapy("www.google.com")
    
    # 4. Traceroute (Linux Server)
    # 리눅스 실습 서버 IP: 210.93.57.50
    traceroute_scapy("www.google.com")
    
    # 파일 저장
    uml.save()