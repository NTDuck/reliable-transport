from typing import Optional
from utils import *


SOCKET_TIMEOUT: float = 0.5

UDP_HEADER_SIZE: int = 8
IP_HEADER_SIZE: int = 20
ETHERNET_FRAME_SIZE: int = 1500
PACKET_HEADER_SIZE: int = 16
PACKET_DATA_SIZE: int = ETHERNET_FRAME_SIZE - UDP_HEADER_SIZE - IP_HEADER_SIZE - PACKET_HEADER_SIZE

PACKET_HEADER_TYPE_START: int = 0
PACKET_HEADER_TYPE_END: int = 1
PACKET_HEADER_TYPE_DATA: int = 2
PACKET_HEADER_TYPE_ACK: int = 3


class Packet:
    def __init__(self, header: PacketHeader, data: Optional[bytes] = None):
        data = data or b""
        self._bytes = bytes(header / data)

    @property
    def header(self) -> PacketHeader:
        return PacketHeader(self._bytes[:PACKET_HEADER_SIZE])

    @property
    def data(self) -> bytes:
        return self._bytes[PACKET_HEADER_SIZE:]

    @classmethod
    def from_bytes(cls, bytes: bytes) -> Packet:
        pkt = cls.__new__(cls)
        pkt._bytes = bytes
        return pkt

    def to_bytes(self) -> bytes:
        return self._bytes
