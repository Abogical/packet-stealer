import socket
import os
from struct import unpack

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

    def __str__(self):
        return (
            f"Protocol: {self.protocol}\n"
            f"IHL: {self.ihl}\n"
            f"From {self.source_address} to {self.destination_address}\n"
            f"Payload: {self.payload}\n"
        )


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

    def __str__(self):
        return (
            f"Port {self.src_port} to port {self.dst_port}\n"
            f"Data offset {self.data_offset}\n"
            f"Payload: {self.payload}\n"
        )


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    return '.'.join(str(int(b)) for b in unpack('!BBBB', raw_ip_addr))


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    res = TcpPacket(-1, -1, -1, b'')
    headers = unpack('!HH8xB', ip_packet_payload[:13])
    res.src_port, res.dst_port = headers[0:2]
    res.data_offset = headers[2] >> 4
    res.payload = ip_packet_payload[res.data_offset*4:]
    return res


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    print(ip_packet)
    res = IpPacket(-1, -1, "0.0.0.0", "0.0.0.0", b'')
    headers = unpack('!B8xB2x4s4s', ip_packet[:20])
    if (headers[0] >> 4) == 4:
        res.ihl = headers[0] & 0xF
        res.protocol = headers[1]
        res.source_address = parse_raw_ip_addr(headers[2])
        res.destination_address = parse_raw_ip_addr(headers[3])
        res.payload = ip_packet[res.ihl*4:]
        return res


def main():
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)
    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    while True:
        # Receive packets and do processing here
        ip_packet = parse_network_layer_packet(stealer.recvfrom(65565)[0])
        print(ip_packet)
        print(parse_application_layer_packet(ip_packet.payload))



if __name__ == "__main__":
    main()
