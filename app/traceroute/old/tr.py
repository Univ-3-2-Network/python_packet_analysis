import argparse
import sys
import os
import socket # 목적지 IP 주소를 확인하기 위해 필요합니다.

# ==========================================
# Traceroute 구현부 (기능을 위해 더미 함수로 정의)
# 실제 Scapy 기반 코드는 여기에 들어갑니다.
# ==========================================
def traceroute(destination, max_hops=30, timeout=2):
    """
    실제 traceroute 로직을 실행하는 함수입니다.
    """
    print("--------------------------------------------------")
    try:
        # 도메인 이름을 IP 주소로 변환
        destination_ip = socket.gethostbyname(destination)
        print(f"[*] Resolved {destination} to {destination_ip}")
        print(f"[*] Starting trace with Max Hops: {max_hops}, Timeout: {timeout}s")

        # 여기서는 실제 패킷 송수신 로직을 생략하고,
        # 정상적인 호출만 보여줍니다.
        
        # for ttl in range(1, max_hops + 1):
        #    # Scapy sr1() 호출 및 ICMP/TTL 분석 로직
        #    pass
        
        # 예시 출력을 위해 마지막 홉만 가정
        print(f" 1  192.168.1.1  1.50ms")
        print(f" 2  10.0.0.1     5.21ms")
        print(f" 3  {destination} ({destination_ip}) <Destination Reached>")
        
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{destination}'. Check the host name or internet connection.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
    print("--------------------------------------------------")


# ==========================================
# Main Function
# ==========================================
def main():
    # Argument Passing
    parser = argparse.ArgumentParser(description="Traceroute implementation in Python.")
    
    # 필수 인자: 목적지 주소
    parser.add_argument("destination", help="Destination host or IP address.")
    
    # 선택적 인자: 최대 홉 수 (-m, --max-hops)
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops (default: 30).")
    
    # 선택적 인자: 타임아웃 (-t, --timeout)
    parser.add_argument("-t", "--timeout", type=int, default=2, help="Timeout for each packet in seconds (default: 2).")

    args = parser.parse_args()
    
    # Printing Information
    print("=" * 60)
    print(f"Traceroute to {args.destination} (max hops: {args.max_hops}, timeout: {args.timeout} seconds):")
    print("=" * 60)
    
    # Calling Traceroute Function
    traceroute(args.destination, max_hops=args.max_hops, timeout=args.timeout)


if __name__ == "__main__":
    # 관리자 권한 확인 (Scapy는 보통 Raw Socket을 위해 필요함)
    if os.geteuid() != 0:
        print("\n[Warning] Running as root (sudo) is usually required for Scapy/traceroute.")
        # sudo 재실행 로직은 생략
    
    main()