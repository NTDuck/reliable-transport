import argparse
import logging
import socket

import argparse
import io
import socket
import sys
from typing import Any

from utils0 import *


def receiver(receiver_ip, receiver_port, window_size):
    """TODO: Listen on socket and print received message to sys.stdout."""

    def make_socket() -> socket.socket:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.bind((receiver_ip, receiver_port))
        skt.settimeout(SOCKET_TIMEOUT)
        return skt

    def send(skt: socket.socket, addr: Any, pkt: Packet) -> None:
        skt.sendto(bytes(pkt), addr)

    def receive(skt: socket.socket, bufsize: int = SOCKET_BUFFER_SIZE) -> tuple[Packet, Any]:
        bytes_, addr = skt.recvfrom(bufsize)
        pkt = Packet(_bytes=bytes_)
        return pkt, addr

    skt = make_socket()

    while True:
        try:
            recv_pkt, addr = receive(skt)
            
            if recv_pkt.header.type == START and recv_pkt.header.seq_num == 0:
                ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=recv_pkt.header.seq_num + 1, length=0))
                send(skt, addr, pkt=ack_pkt)
                logging.info("ACK of START packet transmitted")
                break

        except socket.timeout:
            pass

    data_pkts = []

    skt.close()


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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
