import socket
import struct
import zlib

MAX_SEQ_NUM = 256
SYN = 1
ACK = 2
FIN = 3

# CRC-32 checksum functions
def compute_checksum(seq_num, payload):
    """
    Calculate CRC-32 checksum for the sequence number and payload.
    """
    data = struct.pack("!B", seq_num) + payload
    return zlib.crc32(data) & 0xFFFFFFFF  # Ensure 32-bit checksum

def is_corrupt(packet):
    """
    Check if the packet is corrupted by recalculating its CRC-32 checksum.
    """
    if len(packet) < 6:
        return True
    packet_type, seq_num, checksum = struct.unpack('!B B I', packet[:6])
    payload = packet[6:]
    calculated_checksum = compute_checksum(seq_num, payload)
    return checksum != calculated_checksum

def create_ack_packet(ack_num, packet_type):
    """
    Create an ACK, SYN-ACK, or FIN-ACK packet with a CRC-32 checksum.
    """
    payload = b''  # No payload for ACKs
    checksum = compute_checksum(ack_num, payload)
    return struct.pack('!B B I', packet_type, ack_num, checksum)

def parse_packet(packet):
    """
    Extract the packet type, sequence number, and payload.
    """
    packet_type, seq_num, checksum = struct.unpack('!B B I', packet[:6])
    payload = packet[6:]
    return packet_type, seq_num, payload


def rdt_receive(sock, expected_seq_num):
    buffer = {}  # To store out-of-order packets

    while True:
        try:
            packet, addr = sock.recvfrom(1024)
            if is_corrupt(packet):
                print("Corrupt packet received, ignoring.")
                continue

            packet_type, seq_num, payload = parse_packet(packet)
            
            if packet_type == SYN:
                # Send SYN-ACK
                syn_ack_packet = create_ack_packet(seq_num, SYN)
                sock.sendto(syn_ack_packet, addr)

            elif packet_type == FIN:
                # Send FIN-ACK
                fin_ack_packet = create_ack_packet(seq_num, FIN)
                sock.sendto(fin_ack_packet, addr)
                break

            else:
                if seq_num == expected_seq_num:
                    # Process the expected packet
                    print(f"Received: {payload.decode()}")
                    expected_seq_num = (expected_seq_num + 1) % MAX_SEQ_NUM
                    
                    # Send acknowledgment
                    ack_packet = create_ack_packet(seq_num, ACK)
                    sock.sendto(ack_packet, addr)

                    # Check the buffer for the next expected packets
                    while expected_seq_num in buffer:
                        print(f"Processing buffered packet {expected_seq_num}")
                        print(f"Received (from buffer): {buffer[expected_seq_num].decode()}")
                        del buffer[expected_seq_num]
                        expected_seq_num = (expected_seq_num + 1) % MAX_SEQ_NUM
                        
                elif seq_num > expected_seq_num:
                    # Buffer the out-of-order packet
                    print(f"Out-of-order packet received: {seq_num}, buffering.")
                    buffer[seq_num] = payload
                    
                    # Send acknowledgment for the out-of-order packet
                    ack_packet = create_ack_packet(seq_num, ACK)
                    sock.sendto(ack_packet, addr)
                    
                else:
                    # Duplicate packet, resend ACK
                    print(f"Duplicate packet received: {seq_num}, resending ACK.")
                    ack_packet = create_ack_packet(seq_num, ACK)
                    sock.sendto(ack_packet, addr)

        except OSError as e:
            print(f"Socket error: {e}")
            break

if __name__ == "__main__":
    server_address = ('localhost', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(server_address)
    packet, addr = sock.recvfrom(1024)
    if is_corrupt(packet):
        print("Corrupt packet received")
       

    packet_type, seq_num, payload = parse_packet(packet)
    if packet_type == SYN:
        # Send SYN-ACK
        syn_ack_packet = create_ack_packet(seq_num, SYN)
        sock.sendto(syn_ack_packet, addr)
        print("Connection established")
    rdt_receive(sock, 0)
    
    sock.close()
