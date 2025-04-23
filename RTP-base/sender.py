import argparse
import socket
import sys
from typing import Any

from utils0 import *


def sender(receiver_ip, receiver_port, window_size, msg: bytes | Any = sys.stdin.buffer.read()):
    """TODO: Open socket and send message from sys.stdin."""

    def make_socket() -> socket.socket:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.settimeout(SOCKET_TIMEOUT)
        return skt

    def send(skt: socket.socket, pkt: Packet) -> None:
        skt.sendto(bytes(pkt), (receiver_ip, receiver_port))

    def receive(skt: socket.socket, bufsize: int = BUFFER_SIZE) -> Packet:
        bytes_ = skt.recvfrom(bufsize=bufsize)
        pkt = Packet(bytes_=bytes_)
        return pkt

    skt = make_socket()

    pkt = Packet(header=Packet.Header(type=Packet.Header.Type.START, seq_num=0, length=0))
    send(skt, pkt)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)

if __name__ == "__main__":
    main()
