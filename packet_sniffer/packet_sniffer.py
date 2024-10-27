import socket
import struct
import textwrap

ETHERNET_HEADER_SIZE = 14
IP_HEADER_SIZE = 20
TCP_HEADER_SIZE = 20
UDP_HEADER_SIZE = 8
ICMP_HEADER_SIZE = 8

def format_mac_address(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr).upper()

def format_ip_address(addr):
    return '.'.join(str(x) for x in addr)


def extract_packet_info(packet):
    eth_header = packet[:ETHERNET_HEADER_SIZE]
    eth = struct.unpack('!6s6sH', eth_header)
    dst_mac = format_mac_address(eth[0])
    src_mac = format_mac_address(eth[1])
    eth_type = eth[2]

    print(f'Ethernet frame:')
    print(f'   destination MAC: {dst_mac}')
    print(f'   source MAC: {src_mac}')
    
    if eth_type == 0x0800: 
        ip_header = packet[ETHERNET_HEADER_SIZE:ETHERNET_HEADER_SIZE + IP_HEADER_SIZE]
        ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = ip[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        src_ip = format_ip_address(ip[8])
        dst_ip = format_ip_address(ip[9])
        print(f'   IP cersion: {version}')
        print(f'   source IP: {src_ip}')
        print(f'   destination IP: {dst_ip}')

        protocol = ip[6]
        
        if protocol == 6:  
            tcp_header = packet[ETHERNET_HEADER_SIZE + IP_HEADER_SIZE:ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE]
            tcp = struct.unpack('!HHLLBBHHH', tcp_header)
            src_port = tcp[0]
            dst_port = tcp[1]
            seq_number = tcp[2]
            ack_number = tcp[3]
            flags = tcp[5]
            window_size = tcp[6]
            checksum = tcp[7]

            print(f'TCP segment:')
            print(f'   source port: {src_port}')
            print(f'   destination port: {dst_port}')
            print(f'   sequence number: {seq_number}')
            print(f'   acknowledgment number: {ack_number}')
            print(f'   flags: {flags}')
            print(f'   window size: {window_size}')
            print(f'   checksum: {checksum}')

        if protocol == 17:  
            udp_header = packet[ETHERNET_HEADER_SIZE + IP_HEADER_SIZE:ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE]
            udp = struct.unpack('!HHHH', udp_header)
            src_port = udp[0]
            dst_port = udp[1]
            udp_length = udp[2]
            checksum = udp[3]

            print(f'UDP segment:')
            print(f'   source port: {src_port}')
            print(f'   destination port: {dst_port}')
            print(f'   UDP length: {udp_length}')
            print(f'   checksum: {checksum}')

        elif protocol == 1:  
            icmp_header = packet[ETHERNET_HEADER_SIZE + IP_HEADER_SIZE:ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + ICMP_HEADER_SIZE]
            icmp = struct.unpack('!BBHHH', icmp_header)
            icmp_type = icmp[0]
            code = icmp[1]
            identifier = icmp[2]
            seq_number = icmp[3]
            checksum = icmp[4]

            print(f'ICMP packet:')
            print(f'   type: {icmp_type}')
            print(f'   code: {code}')
            print(f'   identifier: {identifier}')
            print(f'   sequence number: {seq_number}')
            print(f'   checksum: {checksum}')

        payload = packet[ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + (TCP_HEADER_SIZE if protocol == 6 else UDP_HEADER_SIZE if protocol == 17 else ICMP_HEADER_SIZE):]
        print(f'payload data: {payload.hex()}')

def start_sniffer():
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    print('sniffer is running...')
    try:
        while True:
            packet, _ = sock.recvfrom(65535)
            extract_packet_info(packet)
    except KeyboardInterrupt:
        print('sniffer stopped.')
    finally:
        sock.close()

if __name__ == '__main__':
    start_sniffer()
