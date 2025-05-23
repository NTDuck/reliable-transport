import argparse
import logging
import socket
import sys

from utils0 import *


def sender(receiver_ip, receiver_port, window_size):
    """TODO: Open socket and send message from sys.stdin."""

    def make_socket() -> socket.socket:
        skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        skt.settimeout(SOCKET_TIMEOUT)
        return skt

    def send(skt: socket.socket, pkt: Packet) -> None:
        skt.sendto(bytes(pkt), (receiver_ip, receiver_port))
        logging.debug(f"sent PACKET ({pkt})")

    def receive(skt: socket.socket, bufsize: int = SOCKET_BUFFER_SIZE) -> Packet:
        bytes_, _ = skt.recvfrom(bufsize)
        pkt = Packet.from_bytes(bytes_)
        logging.debug(f"recv PACKET ({pkt})")
        return pkt

    skt = make_socket()

    start_pkt = Packet(header=PacketHeader(type=START, seq_num=0, length=0))

    while True:
        send(skt, pkt=start_pkt)
        logging.info("START packet transmitted")
        
        try:
            recv_pkt = receive(skt)
            if recv_pkt.header.type == ACK \
                and recv_pkt.header.seq_num == start_pkt.header.seq_num + 1:
                logging.info("START packet ACK-ed")
                break

        except socket.timeout:
            logging.info("START packet not ACK-ed, sender retransmits")

    msg = sys.stdin.buffer.read()
    msg_chunks = [msg[idx:idx + Packet.DATA_SIZE] \
                  for idx in range(0, len(msg), Packet.DATA_SIZE)]
    data_pkts = [Packet(header=PacketHeader(type=DATA, seq_num=idx, length=len(msg_chunk)), data=msg_chunk) \
                 for idx, msg_chunk in enumerate(msg_chunks)]
    
    curr_idx = 0

    while curr_idx < len(data_pkts):
        idx_window = range(curr_idx, min(curr_idx + window_size, len(data_pkts)))
    
        for idx in idx_window:
            send(skt, pkt=data_pkts[idx])
        logging.info(f"DATA packets {idx_window.start} to {idx_window.stop} transmitted")

        try:
            recv_pkt = receive(skt)
            if recv_pkt.header.type == ACK \
                and recv_pkt.header.seq_num > curr_idx \
                and recv_pkt.header.seq_num < len(data_pkts):
                curr_idx = recv_pkt.header.seq_num
                logging.info(f"DATA packets {idx_window.start} to {idx_window.stop} ACK-ed")

        except socket.timeout:
            logging.info(f"DATA packets {idx_window.start} to {idx_window.stop} not ACK-ed, sender retransmits")

    end_pkt = Packet(header=PacketHeader(type=END, seq_num=len(data_pkts), length=0))

    send(skt, end_pkt)
    logging.info("END packet transmitted")

    try:
        recv_pkt = receive(skt)
        if recv_pkt.header.type == ACK and recv_pkt.header.seq_num == end_pkt.header.seq_num + 1:
            logging.info("END packet ACK-ed, sender terminates")

    except socket.timeout:
        logging.info("END packet not ACK-ed, sender terminates")

    skt.close()


def main():
    logging.basicConfig(level=logging.INFO, format="[SEND] %(message)s", filename=".log")

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
