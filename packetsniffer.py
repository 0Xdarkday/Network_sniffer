import socket
import struct

class EthernetFrame:
    def __init__(self, dest_mac, src_mac, eth_proto, data):
        self.dest_mac = dest_mac
        self.src_mac = src_mac
        self.eth_proto = eth_proto
        self.data = data

class IPv4Packet:
    def __init__(self, version, header_length, ttl, proto, src_ip, dest_ip, data):
        self.version = version
        self.header_length = header_length
        self.ttl = ttl
        self.proto = proto
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.data = data

class ICMPPacket:
    def __init__(self, icmp_type, code, checksum, data):
        self.type = icmp_type
        self.code = code
        self.checksum = checksum
        self.data = data

class TCPPacket:
    def __init__(self, src_port, dest_port, sequence, acknowledgment, flags, data):
        self.src_port = src_port
        self.dest_port = dest_port
        self.sequence = sequence
        self.acknowledgment = acknowledgment
        self.flags = flags
        self.data = data

def parse_ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack("! 6s 6s H", data[:14])
    return EthernetFrame(get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(eth_proto), data[14:])

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def parse_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return IPv4Packet(version, header_length, ttl, proto, get_ip_addr(src_ip), get_ip_addr(dest_ip), data[header_length:])

def get_ip_addr(bytes_addr):
    return '.'.join(map(str, bytes_addr))

def parse_icmp_packet(data):
    icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
    return ICMPPacket(icmp_type, code, checksum, data[4:])

def parse_tcp_packet(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack("! H H L L H", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1
    }
    return TCPPacket(src_port, dest_port, sequence, acknowledgment, flags, data[offset:])

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)
        frame = parse_ethernet_frame(raw_data)
        print("\n Ethernet Frame:")
        print(f"Destination: {frame.dest_mac}, Source: {frame.src_mac}, Protocol: {frame.eth_proto}")

        if frame.eth_proto == 8:
            ipv4_packet = parse_ipv4_packet(frame.data)
            print("\tIPv4 Packet:")
            print(f"\tVersion: {ipv4_packet.version}, Header Length: {ipv4_packet.header_length}, TTL: {ipv4_packet.ttl}")
            print(f"\tProtocol: {ipv4_packet.proto}, Source IP: {ipv4_packet.src_ip}, Destination IP: {ipv4_packet.dest_ip}")

            if ipv4_packet.proto == 1:
                icmp_packet = parse_icmp_packet(ipv4_packet.data)
                print("\tICMP Packet:")
                print(f"\tType: {icmp_packet.type}, Code: {icmp_packet.code}, Checksum: {icmp_packet.checksum}")

            elif ipv4_packet.proto == 6:
                tcp_packet = parse_tcp_packet(ipv4_packet.data)
                print("\tTCP Packet:")
                print(f"\tSource Port: {tcp_packet.src_port}, Destination Port: {tcp_packet.dest_port}")
                print(f"\tSequence: {tcp_packet.sequence}, Acknowledgment: {tcp_packet.acknowledgment}")
                print("\tFlags:")
                for flag, value in tcp_packet.flags.items():
                    print(f"\t\t{flag}: {value}")

if __name__ == "__main__":
    main()
