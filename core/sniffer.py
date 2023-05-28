import socket
from typing import Iterator

from core.filters import Filter, AllMatchFilter
from core.parser import Parser


class PacketSniffer:

    ETH_P_ALL = 0x0003

    def __init__(self, iface: str, parser: Parser, _filter: Filter = AllMatchFilter()):
        self._iface = iface
        self._parser = parser
        self._filter = _filter

    def listen(self) -> Iterator:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL)) as sock:
            sock.bind((self._iface, 0))
            while True:
                frame = sock.recv(2000)
                # print(type(frame), frame)
                if self._filter.match(frame):
                    yield self._parser.parse(frame)


class PacketSender:
    SO_BINDTODEVICE = 25
    ETH_P_ALL = 0x0003

    def __init__(self, iface: str):
        self._iface = iface
        self._socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL))
        self._socket.bind((self._iface, 0))

    def send(self, raw_data: bytes):
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(self.ETH_P_ALL)) as sock:
            sock.bind((self._iface, 0))
            sock.send(raw_data)
        # self._socket.sendall(raw_data)
