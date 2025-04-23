from typing import Optional
from utils import *


SOCKET_TIMEOUT: float = 0.5
BUFFER_SIZE: int = 2048


class Packet:
    class Header(PacketHeader):
        class Type:
            START: int = 0
            END: int = 1
            DATA: int = 2
            ACK: int = 3

        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            self.checksum = compute_checksum(self)

    __UDP_HEADER_SIZE: int = 8
    __IP_HEADER_SIZE: int = 20
    __ETHERNET_FRAME_SIZE: int = 1500
    __PACKET_HEADER_SIZE: int = 16
    PACKET_DATA_SIZE: int = __ETHERNET_FRAME_SIZE - __UDP_HEADER_SIZE - __IP_HEADER_SIZE - __PACKET_HEADER_SIZE

    def __init__(self, header: Optional[Header] = None, data: Optional[bytes] = None, bytes_: Optional[bytes] = None):
        if bytes_:
            self.bytes_ = bytes_
        else:
            self.bytes_ = bytes(header / data)

    @property
    def header(self) -> Header:
        return PacketHeader(self.bytes_[:Packet.__PACKET_HEADER_SIZE])

    @property
    def data(self) -> bytes:
        return self.bytes_[Packet.__PACKET_HEADER_SIZE:]

    def __bytes__(self) -> bytes:
        return self.bytes_
