import socket
import struct
import random
import threading
import time
import zlib 
import json
    
INITIAL_CWND = 1  
SS_THRESH = 16    
TIMEOUT = 1.0
LOSS_PROB = 0.3
ERROR_PROB = 0.05
MAX_SEQ_NUM = 256
SYN = 1
ACK = 2
FIN = 3

def compute_checksum(seq_num, payload):
    if not payload:  
        payload = b''
    data = struct.pack("!B", seq_num) + payload
    return zlib.crc32(data) & 0xFFFFFFFF

def is_corrupt(packet):
    if len(packet) < 6:  
        return True
    packet_type, seq_num, checksum = struct.unpack('!B B I', packet[:6])
    payload = packet[6:]  
    calculated_checksum = compute_checksum(seq_num, payload)
    return checksum != calculated_checksum  


def create_packet(packet_type, seq_num, payload):
    if not payload: 
        payload = b''
    checksum = compute_checksum(seq_num, payload)  
    return struct.pack('!B B I', packet_type, seq_num, checksum) + payload


def parse_ack(packet):
    _, ack_num, _ = struct.unpack('!B B I', packet[:6])
    return ack_num


def rdt_send(sock, data, addr):
    base = 1
    next_seq_num = 1
    window = {}
    timers = {}
    lock = threading.Lock()
    ack_event = threading.Event()

    cwnd = INITIAL_CWND
    ssthresh = SS_THRESH

    def start_timer(seq_num):
        timers[seq_num] = threading.Timer(TIMEOUT, handle_timeout, args=(seq_num,))
        timers[seq_num].start()

    def handle_timeout(seq_num):
        nonlocal cwnd, ssthresh
        with lock:
            if seq_num in window:
                print(f"Timeout: Retransmitting packet {seq_num}")
                send_packet(seq_num, window[seq_num])
                start_timer(seq_num)
                ssthresh = max(cwnd // 2, 1)
                cwnd = 1

    def send_packet(seq_num, payload):
        packet = create_packet(0, seq_num, payload)  
        if random.random() > LOSS_PROB:
            if random.random() < ERROR_PROB:
                packet = corrupt_packet(packet)
            sock.sendto(packet, addr)
    
    def corrupt_packet(packet):
        payload = bytearray(packet[6:])
        corruption_type = random.choice(['corrupt', 'discard'])

        print(f"Original payload (before corruption): {payload}")

        if corruption_type == 'corrupt' and payload:
            # Randomly choose the type of corruption
            corruption_method = random.choice(['single', 'burst', 'random'])
            print(f"Corruption type selected: {corruption_method}")

            if corruption_method == 'single':
                index = random.randint(0, len(payload) - 1)
                payload[index] ^= 0x01
                print(f"Single-bit corruption at index {index}")

            elif corruption_method == 'burst':
                indices = random.sample(range(len(payload)), min(3, len(payload)))
                for index in indices:
                    payload[index] ^= 0xFF
                    print(f"Multiple-byte corruption at index {index}")

            elif corruption_method == 'random':
                for _ in range(min(3, len(payload))):
                    index = random.randint(0, len(payload) - 1)
                    payload[index] ^= 1 << random.randint(0, 7)
                    print(f"Random-bit corruption at index {index}")

        elif corruption_type == 'discard' and payload:
            # Discard a random number of bytes (instead of bits for simplicity)
            num_bytes_to_discard = random.randint(1, len(payload))
            payload = payload[:-num_bytes_to_discard]
            print(f"Discarded {num_bytes_to_discard} bytes from the payload.")

        print(f"Modified payload (after corruption/discard): {payload}")
        return packet[:6] + bytes(payload)

    def sending_thread():
        nonlocal base, next_seq_num, cwnd
        while base < len(data):
            with lock:
                while next_seq_num < base + cwnd and next_seq_num < len(data):
                    send_packet(next_seq_num, data[next_seq_num].encode())
                    print(f"Sent: {next_seq_num + 1}")
                    window[next_seq_num] = data[next_seq_num].encode()
                    start_timer(next_seq_num)
                    next_seq_num += 1
            ack_event.wait()
            ack_event.clear()
        print("done")

    def receive_ack(data):
        nonlocal base, next_seq_num, cwnd, ssthresh
        sock.settimeout(2)
        while base < len(data) or len(window) > 0:
            try:
                packet, _ = sock.recvfrom(1024)
                if random.random() > LOSS_PROB:
                    if is_corrupt(packet):
                        print("Corrupt ACK received")
                        continue
                    ack_num = parse_ack(packet)
                    with lock:
                        if ack_num in window:
                            print(f"ACK received for packet {ack_num}")
                            window[ack_num] = 'ACK'
                            timers[ack_num].cancel()

                            while base in window and window[base] == 'ACK':
                                del window[base]
                                base += 1
                                ack_event.set()

                            if cwnd < ssthresh:
                                cwnd += 1 
                            else:
                                cwnd += 1 / cwnd 
                            print(cwnd)
            except Exception as e:
                print(f"error: {e}")

        print("Done")

    def connect():
        syn_packet = create_packet(SYN, 0, b'')
        sock.sendto(syn_packet, addr)
        print("hel")
        sock.settimeout(5)
        try:
            packet, _ = sock.recvfrom(1024)
            if is_corrupt(packet):
                print("Corrupt SYN-ACK received")
                return False
            print(packet)
            packet_type, seq_num, _ = struct.unpack('!B B H', packet[:4])
            if packet_type == SYN and seq_num == 0:
                ack_packet = create_packet(ACK, 0, b'')
                sock.sendto(ack_packet, addr)
                print("lk")
                return True
        except:
            print("err")
        return False

    def disconnect():
        fin_packet = create_packet(FIN, 0, b'')
        sock.sendto(fin_packet, addr)
        
        sock.settimeout(5)
        try:
            packet, _ = sock.recvfrom(1024)
            if is_corrupt(packet):
                print("Corrupt FIN-ACK received")
                return False
            packet_type, seq_num, _ = struct.unpack('!B B H', packet[:4])
            if packet_type == FIN and seq_num == 0:
                return True
        except socket.timeout:
            print("Disconnection timeout")
        return False

    if not connect():
        print("Failed to establish connection")
        return

    send_thread = threading.Thread(target=sending_thread, daemon=True)
    send_thread.start()

    receive_ack(data)

    send_thread.join()

    if not disconnect():
        print("Failed to disconnect properly")



if __name__ == "__main__":
    server_address = ('localhost', 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    message = ["Message part 1", "Message part 2", "Message part 3", "Message part 4", "Message part 5",
               "Message part 6", "Message part 7", "Message part 8", "Message part 9", "Message part 10"]
    for i in range(11, 100):
        message.append("Message part " + str(i))
    rdt_send(sock, message, server_address)
    sock.close()
