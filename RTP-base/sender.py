import argparse
import logging
import socket
import sys
import time

from utils0 import *


def sender(receiver_ip, receiver_port, window_size):
    """TODO: Open socket and send message from sys.stdin."""

    def make_socket() -> socket.socket:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.setblocking(False)
        return skt

    def send(skt: socket.socket, pkt: Packet) -> None:
        skt.sendto(bytes(pkt), (receiver_ip, receiver_port))

    def receive(skt: socket.socket, bufsize: int = BUFFER_SIZE) -> Packet:
        bytes_ = skt.recvfrom(bufsize)
        pkt = Packet(bytes_=bytes_)
        return pkt

    skt = make_socket()

    start_pkt = Packet(header=PacketHeader(type=START, seq_num=0, length=0))
    is_start_pkt_acked = False

    while not is_start_pkt_acked:
        send(skt, pkt=start_pkt)
        logging.info("START packet transmitted")

        start_pkt_transmitted = time.monotonic()
        while time.monotonic() - start_pkt_transmitted <= SOCKET_TIMEOUT:
            recv_pkt = receive(skt)
            if recv_pkt.header.type == ACK and recv_pkt.header.seq_num == 1:
                is_start_pkt_acked = True
                logging.info("START packet ACK-ed")
                break

    msg = sys.stdin.buffer.read()
    msg_chunks = [msg[idx:idx + Packet.DATA_SIZE] \
                  for idx in range(0, len(msg), Packet.DATA_SIZE)]
    data_pkts = [Packet(header=PacketHeader(type=DATA, seq_num=idx, length=len(msg_chunk))) \
                 for idx, msg_chunk in enumerate(msg_chunks)]
    
    ...
    
    end_pkt = Packet(header=PacketHeader(type=END, seq_num=len(data_pkts), length=0))
    send(skt, end_pkt)
    logging.info("END packet transmitted")

    ...

    skt.close()


def main():
    logging.basicConfig(level = logging.INFO)

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
