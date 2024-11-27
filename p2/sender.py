
import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_addr = ('127.0.0.1', 9999)

# func to create packet with seq number and payload
def create_packet(seq_num, data):
    header = struct.pack('!I', seq_num)
    return header+data


data = b'Hello from Sender\n'
seq_num = 99

packet = create_packet(seq_num, data)


while True:

    sock.sendto(packet,server_addr)
    print(f"Packet Sent: Seq = {seq_num}")

    sock.settimeout(1)

    try:
        ack, _ = sock.recvfrom(1024)
        ack_num = struct.unpack('!I', ack)[0]

        if ack_num == seq_num:
            print("ACK received")
            break
    except socket.timeout:
        print("timeout, retransmitting")
