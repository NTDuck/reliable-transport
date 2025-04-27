import argparse
import logging
import socket
import sys
from io import BytesIO
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
        logging.debug(f"sent PACKET ({pkt})")

    def receive(skt: socket.socket, bufsize: int = SOCKET_BUFFER_SIZE) -> tuple[Packet, Any]:
        bytes_, addr = skt.recvfrom(bufsize)
        pkt = Packet.from_bytes(bytes_)
        logging.debug(f"recv PACKET ({pkt})")
        return pkt, addr

    skt = make_socket()

    while True:
        try:
            recv_pkt, addr = receive(skt)

            if recv_pkt.header.type == START and recv_pkt.header.seq_num == 0:
                ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=1, length=0))
                send(skt, addr, pkt=ack_pkt)
                logging.info("ACK of START packet transmitted")
                
                break

        except socket.timeout:
            pass

    data_pkts_by_seq_nums: dict[int, Packet] = {}
    msg_stream = BytesIO()
    expected_seq_num = 0

    while True:
        seq_num_window = range(expected_seq_num, expected_seq_num + window_size)

        try:
            recv_pkt, addr = receive(skt)

            # if not recv_pkt.verify_checksum():
            #     logging.info("checksum mismatch, packet dropped")
            #     continue

            if recv_pkt.header.type == DATA:
                if recv_pkt.header.seq_num < expected_seq_num:
                    # already received, ignore
                    ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=expected_seq_num, length=0))
                    send(skt, addr, pkt=ack_pkt)
                    logging.info(f"ACK of DATA packet {recv_pkt.header.seq_num} (already received) transmitted")

                elif recv_pkt.header.seq_num == expected_seq_num:
                    # check for the highest sequence number (say M) of the in­order packets it has already received and send ACK with seq_num=M+1.

                    # advance window stuff
                    while expected_seq_num in data_pkts_by_seq_nums:
                        data_pkt = data_pkts_by_seq_nums.pop(expected_seq_num)
                        msg_stream.write(data_pkt.data)
                        expected_seq_num += 1

                    ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=expected_seq_num, length=0))
                    send(skt, addr, pkt=ack_pkt)
                    logging.info(f"ACK of DATA packet {recv_pkt.header.seq_num} (expected) transmitted")

                elif recv_pkt.header.seq_num in seq_num_window:
                    # packet is out of order, buffer

                    if recv_pkt.header.seq_num not in data_pkts_by_seq_nums:
                        data_pkts_by_seq_nums[recv_pkt.header.seq_num] = recv_pkt

                    ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=expected_seq_num, length=0))
                    send(skt, addr, pkt=ack_pkt)
                    logging.info(f"ACK of DATA packet {recv_pkt.header.seq_num} (out-of-order, within window) transmitted")
                    
                # drop all packets with seq_num greater than or equal to N + window_size to maintain a window_size window

            elif recv_pkt.header.type == END:
                ack_pkt = Packet(header=PacketHeader(type=ACK, seq_num=expected_seq_num + 1, length=0))
                send(skt, addr, pkt=ack_pkt)
                
                break
            
        except socket.timeout:
            pass

    # write data to buffer here
    skt.close()

    msg = msg_stream.getvalue()
    sys.stdout.buffer.write(msg)
    sys.stdout.buffer.flush()


def main():
    logging.basicConfig(level=logging.INFO, format="[RECV] %(message)s", filename=".log")

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
