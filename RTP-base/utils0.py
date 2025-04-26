from typing import Optional, Self
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

    def __init__(self, header: PacketHeader, data: Optional[bytes] = None):
        self._header = header
        self._data = data or b""

        self._header.checksum = compute_checksum(bytes(self))

    @property
    def header(self) -> PacketHeader:
        return self._header

    @property
    def data(self) -> bytes:
        return self._data

    def __bytes__(self) -> bytes:
        return bytes(self._header / self._data)
    
    def __repr__(self) -> str:
        return f"type={
            "START" if self.header.type == START else
            "END" if self.header.type == END else
            "DATA" if self.header.type == DATA else
            "ACK"
        }, seq_num={self.header.seq_num}"

    @staticmethod
    def from_bytes(bytes_: bytes) -> Self:
        header = PacketHeader(bytes_[:__class__.__HEADER_SIZE])
        data = bytes_[__class__.__HEADER_SIZE:__class__.__HEADER_SIZE + header.length]

        return Packet(header, data)

    def verify_checksum(self, fn=compute_checksum) -> bool:
        persisted_checksum = self._header.checksum
        self._header.checksum = 0

        computed_checksum = fn(bytes(self))
        self._header.checksum = persisted_checksum

        return persisted_checksum == computed_checksum
