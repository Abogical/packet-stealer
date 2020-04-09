import socket
import os
from struct import unpack, unpack_from

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


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    return "0.0.0.0"


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    return TcpPacket(-1, -1, -1, b'')


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    print(ip_packet)
    return IpPacket(-1, -1, "0.0.0.0", "0.0.0.0", b'')


def main():
    if os.name == 'nt':
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((socket.gethostbyname(socket.gethostname()), 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        stealer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        # Receive packets and do processing here
        parse_network_layer_packet(stealer.recvfrom(65565)[0])



if __name__ == "__main__":
    main()
