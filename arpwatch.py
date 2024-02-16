import argparse
import os
import sys
from scapy.all import sniff, ARP
import netifaces


def get_default_iface_name():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, =  line.strip().split()
                if dest != '00000000' or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue


def read_arp_cache():
    """Reads the current ARP cache entries."""
    arp_cache = {}
    with open('/proc/net/arp', 'r') as f:
        for line in f.readlines()[1:]:  # Skip the first line which is the header
            parts = line.split()
            ip = parts[0]
            mac = parts[3]
            if mac != '00:00:00:00:00:00':  # Ignore incomplete entries
                arp_cache[ip] = mac
    return arp_cache


def process_packet(packet, arp_cache):
    """Processes each ARP packet and checks for changes in MAC-IP bindings."""
    if packet.haslayer(ARP) and packet[ARP].op in (1, 2):  # ARP request or response
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in arp_cache and arp_cache[ip] != mac:
            print(f"{ip} changed from {arp_cache[ip]} to {mac}")

        arp_cache[ip] = mac


def main():
    parser = argparse.ArgumentParser(description='ARP Poisoning Attack Detector')
    parser.add_argument('-i', '--interface', help='Network device to listen on', default=get_default_iface_name())
    args = parser.parse_args()

    arp_cache = read_arp_cache()
    print(f"Listening on interface {args.interface}")
    sniff(iface=args.interface, filter="arp", prn=lambda packet: process_packet(packet, arp_cache), store=0)


if __name__ == '__main__':
    main()
