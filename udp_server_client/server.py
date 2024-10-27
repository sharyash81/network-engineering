import socket
import threading
import time
import os

BUFFER_SIZE = 1024

def handle_client(sock, client_address, packets, packet_lock):
    print(f"Connected to {client_address}")
    
    total_packets = len(packets)
    sock.sendto(f"{total_packets}".encode(), client_address)

    ack_received = set()  
    while ack_received != set(range(total_packets)):
        for seq_num, packet in packets.items():
            if seq_num not in ack_received:
                sock.sendto(f"{seq_num:08d}".encode() + packet, client_address) 
                time.sleep(0.001)  

        try:
            data, _ = sock.recvfrom(1024)
            if data.startswith(b'ACK'):
                seq_num = int(data[3:].decode())
                with packet_lock:
                    ack_received.add(seq_num)  
        except socket.timeout:
            continue 

    print(f"File transfer complete for {client_address}")

def server(file_path):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 12345))
    sock.settimeout(5)

    packets = {}
    with open(file_path, 'rb') as f:
        seq_num = 0
        while chunk := f.read(BUFFER_SIZE):
            packets[seq_num] = chunk
            seq_num += 1

    packet_lock = threading.Lock()
    
    print("Server is ready to receive connections.")
    while True:
        data, client_address = sock.recvfrom(1024)
        if data == b'REQUEST':
            threading.Thread(target=handle_client, args=(sock, client_address, packets, packet_lock)).start()

server("large_file.dat")
