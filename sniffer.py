#!/usr/bin/env python

import sys
from scapy.all import *

def resolve_ip_to_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return None

def sniff_traffic(victim_ip):
    def process_packet(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            if src_ip == victim_ip or dst_ip == victim_ip:
                domain = resolve_ip_to_domain(dst_ip)
                if domain:
                    print(f"Packet: {src_ip} -> {dst_ip} (Domain: {domain})")
                else:
                    print(f"Packet: {src_ip} -> {dst_ip} (Domain: Unknown)")

    sniff(prn=process_packet, filter="ip", store=0)

def main():
    victim_ip = sys.argv[1]
    print("Sniffing traffic for:", victim_ip)
    
    sniff_traffic(victim_ip)

if __name__ == "__main__":
    main()
