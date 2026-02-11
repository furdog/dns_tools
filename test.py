import socket

# The target DNS server (Google's Public DNS) and port
DNS_IP = "7.7.7.7"
DNS_PORT = 53

# This is a raw hex represention of a DNS query for "google.com"
# Header: ID=0x1234, Flags=0x0100 (Standard query)
# Question: google.com, Type=A, Class=IN
packet = bytes.fromhex("12340100000100000000000006676f6f676c6503636f6d0000010001")

# Create a UDP socket (SOCK_DGRAM)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    # Send the packet
    print(f"Sending DNS query to {DNS_IP}...")
    sock.sendto(packet, (DNS_IP, DNS_PORT))
    print("Packet sent successfully.")
    
finally:
    sock.close()
