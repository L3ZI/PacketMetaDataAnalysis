from scapy.all import *
from scapy.layers.dhcp import DHCP

# Set the threshold for DHCP requests per second
threshold = 10

# Initialize the DHCP request count
dhcp_request_count = 0

# Initialize the last DHCP request time
last_dhcp_request_time = datetime.now()


def process_dhcp_packet(packet):
    global dhcp_request_count, last_dhcp_request_time

    # Increment the DHCP request count
    dhcp_request_count += 1

    # Check if the DHCP request count exceeds the threshold
    if dhcp_request_count > threshold:
        # Calculate the time difference between the current DHCP request and the last one
        time_diff = datetime.now() - last_dhcp_request_time

        # Check if the time difference is less than 1 second
        if time_diff.total_seconds() < 1:
            # Drop the packet
            print("Dropping DHCP packet due to rate limit")
            pass

            # Reset the DHCP request count
            dhcp_request_count = 0

        # Update the last DHCP request time
        last_dhcp_request_time = datetime.now()

    # Print the DHCP packet summary
    print("DHCP Packet Detected:")
    packet.source = packet.src
    packet.destination = packet.dst
    print(packet.summary())
    packet[DHCP].show()

    file_write = open("logs/dhcp_capture.txt", "a")
    file_write.write(f"DHCP Packet Detected:\n")
    file_write.write(f"Source MAC: {packet.src}\n")
    file_write.write(f"Destination MAC: {packet.dst}\n")
    file_write.write(f"DHCP Data: {packet.summary()}\n")
    file_write.close()

# Sniff for DHCP packets
sniff(filter="port 67 or port 68", prn=process_dhcp_packet)
