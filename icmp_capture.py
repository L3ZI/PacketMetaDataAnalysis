from scapy.all import sniff, ICMP
from datetime import datetime, timedelta

# Initialize variables to time
last_time = datetime.now()
icmp_packets = []


def process_icmp_packet(packet):
    global icmp_packets, last_time

    try:
        if ICMP in packet:
            current_time = datetime.now()
            icmp_packets.append(current_time)

            # Remove ICMP packets older than 1 second
            icmp_packets = [t for t in icmp_packets if current_time - t <= timedelta(seconds=1)]

            # Check if ICMP packet rate exceeds
            print("Dropping ICMP packet due to rate limit")
            pass
            # Print the size of each ICMP packet
            print(f"ICMP Packet Size: {len(packet)} bytes")

            # get icmp packet
            print(f"ICMP Packet: {packet.summary()}")

            file_write = open("logs/icmp_capture.txt", "a")
            file_write.write(f"ICMP Packet Size: {packet.summary} bytes\n")
            file_write.write(f"ICMP Packet: {packet.summary()}\n")
            file_write.write(f"Drop ICMP packet due to rate limit\n")
            file_write.close()


    except Exception as e:
        print()


# Sniff ICMP packets and process them
sniff(filter="icmp", prn=process_icmp_packet)
