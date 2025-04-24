from typing import Optional
from utils import *


SOCKET_TIMEOUT: float = 0.5
BUFFER_SIZE: int = 2048

START: int = 0
END: int = 1
DATA: int = 2
ACK: int = 3


class Packet:
    __UDP_HEADER_SIZE: int = 8
    __IP_HEADER_SIZE: int = 20
    __ETHERNET_FRAME_SIZE: int = 1500
    __HEADER_SIZE: int = 16
    DATA_SIZE: int = __ETHERNET_FRAME_SIZE - __UDP_HEADER_SIZE - __IP_HEADER_SIZE - __HEADER_SIZE

    def __init__(self, header: Optional[PacketHeader] = None, data: Optional[bytes] = None, bytes_: Optional[bytes] = None):
        if bytes_:
            self.bytes_ = bytes_
        else:
            if data:
                bytes_ = header / data
            else:
                bytes_ = header
            header.checksum = compute_checksum(bytes_)
            self.bytes_ = bytes(bytes_)

    @property
    def header(self) -> PacketHeader:
        return PacketHeader(self.bytes_[:__class__.__HEADER_SIZE])

    @property
    def data(self) -> bytes:
        return self.bytes_[__class__.__HEADER_SIZE:]

    def __bytes__(self) -> bytes:
        return self.bytes_

    def is_ack_of(self, pkt: Packet) -> bool:
        return self.header.type == ACK and self.header.seq_num == pkt.header.seq_num + 1
