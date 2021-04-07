import socket
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload

    def display_ip_packet(self):
        print(f"protocol:", self.protocol)
        print(f"IHL:", self.ihl)
        print(f"source:", self.source_address)
        print(f"Destination:", self.destination_address)
        print(f"TCP_PACKET as BYTES:", self.payload)
        print('\n')


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload

    def display_tcp_packet(self):
        print(f"Source Port :", self.src_port)
        print(f"Destination Port :", self.dst_port)
        print(f"Data Offset :", self.data_offset)
        print(f"TCP_PACKET Payload as BYTES :", self.payload)
        print('\n')


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    decoded_ip_addr = socket.inet_ntoa(raw_ip_addr)
    return decoded_ip_addr


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    src_port,dst_port,seq,ack,reserved_flags=struct.unpack('! H H L L H',ip_packet_payload[:14])
    data_offset =(reserved_flags >>12)
    payload = ip_packet_payload[32:]
    try:
        payload2 = payload.decode("UTF-8")
        print("TCP_PACKET data can be decoded!")
        print(payload2)
        print('\n')
    except:
        payload2 = None
        print("An exception occurred")
        print("TCP_PACKET data can't be decoded!")
        print("\n")
    return TcpPacket(src_port, dst_port, data_offset, payload)


def parse_network_layer_packet(ip_packet):
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    first_byte=ip_packet[0]
    #ihl=(first_byte & 0x0F)
    ihl=(first_byte & 15)
    protocol,source ,destination=struct.unpack('! 9x B 2x 4s 4s',ip_packet[:20])
    payload=ip_packet[20:]
    mapped_source=map(str,source)
    mapped_destination=map(str,destination)
    source_string='.'.join(mapped_source)
    destination_string='.'.join(mapped_destination)
    return IpPacket(protocol,ihl, source_string, destination_string, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW,6)

    while True:
        # Receive packets and do processing here
        data, address = stealer.recvfrom(4096)
        #decoded_ip_addr=parse_raw_ip_addr(address)
        #print(f"Decoded IP Address :", decoded_ip_addr)
        ip_obj=parse_network_layer_packet(data)
        IpPacket.display_ip_packet(ip_obj)
        tcp_obj=parse_application_layer_packet(ip_obj.payload)
        TcpPacket.display_tcp_packet(tcp_obj)



if __name__ == "__main__":
    main()
