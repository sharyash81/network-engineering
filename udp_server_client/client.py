import socket
import threading

BUFFER_SIZE = 1024

def receive_packet(sock, total_packets, data_buffer, missing_packets, lock):
    retries = 3  
    while missing_packets:
        try:
            packet, _ = sock.recvfrom(BUFFER_SIZE + 8)
            seq_num = int(packet[:8].decode())
            data = packet[8:]

            
            with lock:
                if seq_num not in data_buffer:
                    data_buffer[seq_num] = data
                    missing_packets.discard(seq_num)

            
            sock.sendto(f"ACK{seq_num:08d}".encode(), ("127.0.0.1", 12345))
        
        except socket.timeout:
            retries -= 1
            if retries == 0:
                print("Connection timeout. Retrying...")
                retries = 3  # Reset retries after a brief delay
                continue

def client():
    server_address = ("127.0.0.1", 12345)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    
    sock.sendto(b'REQUEST', server_address)

    total_packets = int(sock.recvfrom(1024)[0].decode())
    
    data_buffer = {}
    missing_packets = set(range(total_packets))
    lock = threading.Lock()

    threads = [threading.Thread(target=receive_packet, args=(sock, total_packets, data_buffer, missing_packets, lock)) for _ in range(8)]
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    with open("received_file.dat", 'wb') as f:
        for i in range(total_packets):
            f.write(data_buffer[i])

client()
