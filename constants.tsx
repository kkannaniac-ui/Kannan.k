
import React from 'react';

export const BLACKLISTED_IPS = [
  '192.168.1.105',
  '45.33.22.11',
  '103.22.201.25',
  '185.122.11.10'
];

export const PYTHON_CODE = `
import socket
import struct
import textwrap
import time
import datetime
from collections import defaultdict

# --- CONFIGURATION ---
BLACKLIST = ["192.168.1.105", "45.33.22.11"]
THRESHOLD_PORT_SCAN = 10  # Different ports from same IP
THRESHOLD_FAILED_CONN = 5 # Same port from same IP in short burst
LOG_FILE = "nids_threats.log"

# Tracking state
connection_attempts = defaultdict(list)
port_scan_attempts = defaultdict(set)

def log_threat(threat_type, source_ip, details):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    entry = f"[{timestamp}] ALERT: {threat_type} from {source_ip} - {details}"
    print(f"\\033[91m{entry}\\033[0m")
    with open(LOG_FILE, "a") as f:
        f.write(entry + "\\n")

def analyze_packet(data):
    # Unpack Ethernet Frame
    dest_mac, src_mac, eth_proto, data = ethernet_frame(data)
    
    # 8 is IPv4
    if eth_proto == 8:
        (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
        
        # Check Blacklist
        if src in BLACKLIST:
            log_threat("Blacklisted IP", src, "Traffic detected from a known malicious source.")

        # TCP Analysis
        if proto == 6:
            src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
            
            # Port Scan Detection Logic
            port_scan_attempts[src].add(dest_port)
            if len(port_scan_attempts[src]) > THRESHOLD_PORT_SCAN:
                log_threat("Port Scanning", src, f"Accessed {len(port_scan_attempts[src])} unique ports.")
                port_scan_attempts[src].clear()

            # Multiple Failed/Connection Attempt Detection
            now = time.time()
            connection_attempts[(src, dest_port)].append(now)
            # Clean old attempts (> 10s)
            connection_attempts[(src, dest_port)] = [t for t in connection_attempts[(src, dest_port)] if now - t < 10]
            
            if len(connection_attempts[(src, dest_port)]) > THRESHOLD_FAILED_CONN:
                log_threat("Potential Brute Force / Excessive Traffic", src, f"Target Port: {dest_port}")
                connection_attempts[(src, dest_port)].clear()

def main():
    print("--- GuardiaNIDS Python Core Starting ---")
    # Use raw socket to capture all traffic (requires sudo/admin)
    try:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    except PermissionError:
        print("Error: Permission denied. Run with sudo/Admin.")
        return

    while True:
        raw_data, addr = conn.recvfrom(65536)
        analyze_packet(raw_data)

# Helper functions for unpacking...
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

if __name__ == "__main__":
    main()
`;

export const REQUIREMENTS_TXT = `
# Requirements for GuardiaNIDS Python Core
# No external libraries needed for standard raw sockets on Linux.
# For Windows support or advanced parsing, use scapy:
# scapy==2.5.0
`;
