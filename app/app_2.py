#!/usr/bin/env python3
import socket
import struct
import time
import pcapy
import dns.message
import dns.rdatatype

MAX_BYTES = 65535
PROMISCUOUS = 1
TIMEOUT_MS = 100  # capture timeout

def open_sniffer(dev, bpf_filter):
    cap = pcapy.open_live(dev, MAX_BYTES, PROMISCUOUS, TIMEOUT_MS)
    cap.setfilter(bpf_filter)
    return cap

def parse_ip_header(packet):
    eth_len = 14
    ip_header = packet[eth_len:eth_len + 20]
    iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = iph[0]
    ihl = version_ihl & 0x0F
    iph_len = ihl * 4
    protocol = iph[6]
    src = socket.inet_ntoa(iph[8])
    dst = socket.inet_ntoa(iph[9])
    return eth_len, iph_len, protocol, src, dst

def curl_like(dev, host, path="/"):
    addr = socket.gethostbyname(host)
    print(f"[curl] GET http://{host}{path} ({addr})")
    cap = open_sniffer(dev, f"tcp and host {addr} and port 80")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((addr, 80))
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode("ascii"))
    start = time.time()

    while True:
        header, packet = cap.next()
        if not header:
            if time.time() - start > 5:
                break
            continue

        eth_len, iph_len, proto, src, dst = parse_ip_header(packet)
        if proto != 6:  # TCP only
            continue
        t = eth_len + iph_len
        tcp_header = packet[t:t + 20]
        tcph = struct.unpack("!HHLLBBHHH", tcp_header)
        src_port, dst_port = tcph[0], tcph[1]
        data_offset = (tcph[4] >> 4) * 4
        h_size = eth_len + iph_len + data_offset
        data = packet[h_size:]
        if data:
            try:
                text = data.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            if text:
                print("----- HTTP payload (first chunk) -----")
                print(text[:512])
                break

    s.close()

def ping_like(dev, host, count=4):
    dest_ip = socket.gethostbyname(host)
    print(f"[ping] {host} ({dest_ip})")
    cap = open_sniffer(dev, f"icmp and host {dest_ip}")
    icmp_proto = socket.getprotobyname("icmp")
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)

    def checksum(data):
        s = 0
        n = len(data)
        i = 0
        while i < n - 1:
            s += (data[i] << 8) + data[i+1]
            i += 2
        if n % 2:
            s += data[-1] << 8
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return (~s) & 0xffff

    pid = 0x1234
    seq = 1

    for _ in range(count):
        header = struct.pack("!BBHHH", 8, 0, 0, pid, seq)
        payload = struct.pack("!d", time.time())
        cs = checksum(header + payload)
        header = struct.pack("!BBHHH", 8, 0, cs, pid, seq)
        packet = header + payload
        s.sendto(packet, (dest_ip, 0))
        send_time = time.time()

        while True:
            hdr, pkt = cap.next()
            if not hdr:
                if time.time() - send_time > 2:
                    print("Request timed out")
                    break
                continue

            eth_len, iph_len, proto, src, dst = parse_ip_header(pkt)
            if proto != 1:  # ICMP
                continue
            offset = eth_len + iph_len
            icmp_header = pkt[offset:offset+8]
            icmp_type, code, cs2, r_id, r_seq = struct.unpack("!BBHHH", icmp_header)
            if icmp_type == 0 and r_id == pid and r_seq == seq:
                recv_time = time.time()
                rtt = (recv_time - send_time) * 1000
                print(f"Reply from {src}: time={rtt:.2f} ms")
                break

        seq += 1
        time.sleep(1)

    s.close()

def traceroute_like(dev, host, max_hops=30):
    dest_ip = socket.gethostbyname(host)
    print(f"[traceroute] {host} ({dest_ip})")
    cap = open_sniffer(dev, "icmp")
    port = 33434

    for ttl in range(1, max_hops + 1):
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock.settimeout(2)
        send_sock.sendto(b"", (dest_ip, port))
        send_time = time.time()
        addr = None

        while True:
            hdr, pkt = cap.next()
            if not hdr:
                if time.time() - send_time > 2:
                    break
                continue

            eth_len, iph_len, proto, src, dst = parse_ip_header(pkt)
            if proto != 1:
                continue
            offset = eth_len + iph_len
            icmp_header = pkt[offset:offset+8]
            icmp_type, code, cs, _, _ = struct.unpack("!BBHHH", icmp_header)
            addr = src
            break

        recv_sock.close()
        send_sock.close()

        if addr is None:
            print(f"{ttl}\t*")
        else:
            print(f"{ttl}\t{addr}")
            if addr == dest_ip:
                break

def nslookup_like(dev, host, dns_server="8.8.8.8"):
    print(f"[nslookup] {host} using {dns_server}")
    cap = open_sniffer(dev, f"udp and host {dns_server} and port 53")

    q = dns.message.make_query(host, dns.rdatatype.A)
    wire = q.to_wire()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(wire, (dns_server, 53))
    start = time.time()

    while True:
        hdr, pkt = cap.next()
        if not hdr:
            if time.time() - start > 5:
                print("DNS timeout")
                break
            continue

        eth_len, iph_len, proto, src, dst = parse_ip_header(pkt)
        if proto != 17:  # UDP
            continue
        offset = eth_len + iph_len
        udp_header = pkt[offset:offset+8]
        src_port, dst_port, length, csum = struct.unpack("!HHHH", udp_header)
        if dst_port < 1024:
            # probably response from server
            data = pkt[offset+8:]
            try:
                resp = dns.message.from_wire(data)
                for ans in resp.answer:
                    for item in ans.items:
                        if item.rdtype == dns.rdatatype.A:
                            print(f"{host} has address {item.address}")
                break
            except Exception:
                continue

    sock.close()

def main():
    devs = pcapy.findalldevs()
    if not devs:
        print("No interfaces found")
        return
    dev = devs[0]
    print(f"Using interface: {dev}")

    target = "example.com"
    curl_like(dev, target, "/")
    ping_like(dev, target)
    traceroute_like(dev, target)
    nslookup_like(dev, target)

if __name__ == "__main__":
    main()
