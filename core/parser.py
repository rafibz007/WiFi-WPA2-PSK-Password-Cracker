from abc import ABC, abstractmethod

from core.frame import EthernetFrame, EthernetFrame, Frame, RawFrame


class Parser(ABC):
    @abstractmethod
    def parse(self, frame: bytes) -> Frame:
        ...


class EthernetParser(Parser):

    def parse(self, raw_packet: bytes) -> EthernetFrame:
        src: str = ":".join(map(lambda byte: hex(byte).lstrip("0x"), raw_packet[6:12]))
        dst: str = ":".join(map(lambda byte: hex(byte).lstrip("0x"), raw_packet[0:6]))
        type_len: str = raw_packet[12:14].hex()
        data: str = raw_packet[14:-4].hex()
        crc: str = raw_packet[-4:-1].hex()

        return EthernetFrame(src, dst, type_len, data, crc)


class RawDataParser(Parser):

    def parse(self, frame: bytes) -> RawFrame:
        return RawFrame(frame)
