from typing import Optional
from utils import *


SOCKET_TIMEOUT: float = 0.5
SOCKET_BUFFER_SIZE: int = 2048

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

    def __init__(self, header: Optional[PacketHeader] = None, data: Optional[bytes] = None, _bytes: Optional[bytes] = None):
        if _bytes:
            self.bytes_ = _bytes
        else:
            if data:
                _bytes = header / data
            else:
                _bytes = header
            header.checksum = compute_checksum(_bytes)
            self.bytes_ = bytes(_bytes)

    @property
    def header(self) -> PacketHeader:
        if self._header is None:
            self._header = PacketHeader(self.bytes_[:__class__.__HEADER_SIZE])
        return self._header

    @property
    def data(self) -> bytes:
        return self.bytes_[__class__.__HEADER_SIZE:__class__.__HEADER_SIZE + self.header.length]

    def __bytes__(self) -> bytes:
        return self.bytes_

    # def is_ack_of(self, pkt: Packet) -> bool:
    #     return self.header.type == ACK and self.header.seq_num == pkt.header.seq_num + 1
