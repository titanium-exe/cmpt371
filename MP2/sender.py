import socket 
import struct 
import random 
import threading
import zlib 

INITIAL_CWND  = 1
ss_THRESH = 16 
TIMEOUT = 1.0
LOSS_PROB = 0.1
ERROR_PROB = 0.05
MAX_SEQ_NUM = 256
SYN = 1 
ACK = 2 
FIN = 3 


def compute_checksum(seq_num, payload):
    data = struct.pack("!B", seq_num) + playload
    return zlib.crc32(data) & 0xFFFFFFFF 


def is_corrupt(packet):
    
    # 6 bytes header
    packet_type, seq_num, checksum = struct.unpack('!B B I', packet[:6])
    payload = packet[:6]
    
    computed_cs = compute_checksum(seq_num, payload)
    return checksum != computed_cs


def create_packet(packet_type, seq_num, payload):

    checksum = compute_checksum(seq_num, payload)
    return struct.pack('!B B I', packet_type, seq_num, checksum) + payload


def parse_ack(packet):
    _, ack_num, _ = struct.unpack('!B B I', packet[:6])
    return ack_num


def corrupt_data(packet):
    payload = bytearray(packet[6:])
    corruption_type = random.choice(['corrupt', 'discard'])

    if corruption_type == 'corrupt':
        corruption_method = random.choice(['single', 'multiple', 'random'])
        if corruption_method == 'single' and payload:
            random_byte = random.randint(0, len(payload) - 1)
            payload[random_byte] ^= 0x01
        elif corruption_method == 'multiple' and len(payload) >= 3:
            start = random.randint(0, len(payload) - 3)
            for i in range(start, start + 3):
                payload[i] ^= 0xFF
        elif corruption_method == 'random' and payload:
            num_corruptions = min(3, len(payload))
            for _ in range(num_corruptions):
                random_byte = random.randint(0, len(payload) - 1)
                random_bit = 1 << random.randint(0, 7)
                payload[random_byte] ^= random_bit
        else:
            if payload:
                payload[-1] ^= 0x01

    elif corruption_type == 'discard':
        if len(payload) > 0:
            num_bits_to_discard = random.choice([1, 2, 3, 4,5,6,7,8])
            total_bits = len(payload) * 8
            if total_bits >= num_bits_to_discard:
                total_bits -= num_bits_to_discard
                new_byte_length = (total_bits + 7) // 8
                payload = payload[:new_byte_length]
                if total_bits % 8 != 0:
                    remaining_bits = total_bits % 8
                    mask = (1 << remaining_bits) - 1
                    payload[-1] &= mask
            else:
                payload[-1] &= 0xFE

    return packet[:6] + bytes(payload)



def rdt_send(sock, data, addr):
    base = 1
    next_seq_num = 1
    window  = {}
    timers = {}

    lock = threading.Lock()
    ack_event = threading.Event()


    cwnd = INITIAL_CWND
    ssthresh = SS_THRESH

    def start_timer(seq_num):
        nonlocal cwnd, ssthresh
        with lock:
            if seq_num in window:
                print(f"Timeout: Retransmitting packer {seq_num}")
                
                send_packet(seq_num, window[seq_num])
                start_timer(seq_num)
                ssthersh = max(cwnd //2,1)
                cwnd = 1

    def send_packet(seq_num, payload):
        packet = create_packet(0,seq_num,payload)
        if random.random() > LOSS_PROB:
            if random.random() < ERROR_PROB:
                packet = corrupt_packet(packet)
            sock.sendto(packet,addr)
   

    def send_thread():
        nonlocal base, next_seq_num, cwnd

        while base < len(data):
            with lock:
                while next_seq_num < base + cwnd and next_seq_num < len(data):
                    send_packet(next_seq_num, data[next_seq_num].encode())
                    print(f"Sent packet {next_seq_num}")
                    window[next_seq_num] = data[next_seq_num].encode()
                    start_timer(next_seq_num)
                    next_seq_num += 1
            ack_event.wait()
            ack_event.clear()
        print("packets sent")
    

























