import socket

from scapy.all import sniff, ARP
from scapy.layers.l2 import arping

# List of authorized IPs
authorized_ips = ['192.168.1.1']


def get_hostname(ip_address):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror:
        return "Unknown"


def get_arp_ips(subnet):
    responses, unanswered = arping(subnet)
    result = []

    for response in responses:
        if len(response) != 2:
            print("Unexpected response format")
            return result

        sent_packet, received_packet = response
        result.append((received_packet.psrc, received_packet.hwsrc))

    return result


def process_packet(packet):
    if ARP in packet:
        src_ip = packet[ARP].psrc

        # Check if the source IP is authorized
        if src_ip not in authorized_ips:
            print (f"Detected ARP packet from unauthorized IP: {src_ip} and dropping...")
            pass

        print("ARP Packet:")
        print(packet[ARP].summary())

        subnet = '192.168.1.0/24'
        get_arp_ips(subnet)
        print("get arp ips", get_arp_ips(subnet))

        file_write = open("logs/arp_capture.txt", "a")
        file_write.write(f"ARP Packet from {src_ip}, packet summary: {packet[ARP].summary()}\t")
        file_write.write(f"Source IP: , {src_ip}\t")
        file_write.write(f"get arp ips: , {get_arp_ips(subnet)}\t")
        file_write.write(f"Destination IP: , {packet[ARP].pdst}\t")
        file_write.write(f"Source MAC: , {packet[ARP].hwsrc}\t")
        file_write.write(f"Hostname: , {get_hostname(src_ip)}\t")
        file_write.close()


# Sniff ARP packets and process them
while True:
    sniff(filter="arp", prn=process_packet)
