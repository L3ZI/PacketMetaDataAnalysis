from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from collections import defaultdict
from datetime import datetime, timedelta

# Dictionary to store the timestamp of the last DNS request from each IP
dns_request_times = defaultdict(list)

# List of trusted DNS servers
trusted_dns_servers = ['8.8.8.8', '8.8.4.4', '192.168.1.3', '192.168.1.1']


def extract_dns_data(packet):
    if IP not in packet:
        return  # Ignore non-IP packets

    if DNS in packet and UDP in packet:
        src_ip = packet[IP].src

        # DNS Request Rate Limiting
        current_time = datetime.now()
        dns_request_times[src_ip].append(current_time)

        # Remove timestamps older than 1 second
        dns_request_times[src_ip] = [t for t in dns_request_times[src_ip]
                                     if current_time - t <= timedelta(seconds=1)]

        # If more than 10 requests in the last second, drop the packet
        if len(dns_request_times[src_ip]) > 10:
            print(f"Dropping packet due to rate limit: {src_ip}")
            pass

        # DNS Response Validation
        if DNSRR in packet:
            if packet[IP].src not in trusted_dns_servers:
                print(f"Dropping packet from untrusted DNS server: {packet[IP].src}")
                pass

        file_write = open("logs/dns_capture.txt", "a")
        file_write.write(f"DNS Packet from {src_ip}\n")
        file_write.write(f"Drop packet due to rate limit: {src_ip}\n")
        file_write.write(f"DNS Data: {packet.summary()}\n")
        file_write.close()

        print("DNS Data:")
        print(packet.summary())


# Sniff UDP packets and extract DNS data
while True:
    sniff(filter="udp", prn=extract_dns_data)
