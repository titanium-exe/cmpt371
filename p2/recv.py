import socket
import struct

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to an IP address and port
sock.bind(('127.0.0.1', 9999))  # Receiver's IP and port
print("Waiting for packets...")

while True:
    try:
        # Receive a packet from the sender
        packet, address = sock.recvfrom(1024)  # Buffer size of 1024 bytes
        
        # Extract the sequence number from the packet
        seq_num = struct.unpack('!I', packet[:4])[0]  # First 4 bytes are the sequence number
        data = packet[4:]  # The rest is the payload
        
        # Print the received packet details
        print(f"Received packet: Seq={seq_num}, Data={data.decode()}")
        
        # Create and send an ACK
        ack = struct.pack('!I', seq_num)  # ACK includes the sequence number
        sock.sendto(ack, address)
        print(f"ACK sent for Seq={seq_num}")
    except Exception as e:
        # Handle any unexpected errors gracefully
        print(f"An error occurred: {e}")

