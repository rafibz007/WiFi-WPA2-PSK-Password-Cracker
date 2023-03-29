from abc import ABC, abstractmethod
from typing import Tuple

from core.frame import EthernetFrame, Frame, RawFrame, ManagementFrame, ManagementFrameRadioTapHeader, \
    ManagementFrameFrameControl


class Parser(ABC):
    @abstractmethod
    def parse(self, frame: bytes) -> Frame:
        ...


class EthernetParser(Parser):

    def parse(self, raw_packet: bytes) -> EthernetFrame:
        src: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), raw_packet[6:12]))
        dst: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), raw_packet[0:6]))
        type_len: str = raw_packet[12:14].hex()
        data: str = raw_packet[14:-4].hex()
        crc: str = raw_packet[-4:-1].hex()

        return EthernetFrame(src, dst, type_len, data, crc)


class RawDataParser(Parser):

    def parse(self, frame: bytes) -> RawFrame:
        _, frame = RadioTapHeaderParser.parse(frame)
        return RawFrame(frame)


class RadioTapHeaderParser:

    @staticmethod
    def parse(frame: bytes) -> Tuple[ManagementFrameRadioTapHeader, bytes]:
        version = hex(frame[0])
        pad = hex(frame[1])
        header_length = int.from_bytes(frame[2:4], "little")
        return ManagementFrameRadioTapHeader(
            version, pad, header_length
        ), frame[header_length:]



getbinary = lambda x, n: format(x, 'b').zfill(n)


class ManagementFrameFrameControlParser:

    @staticmethod
    def parse(frame_control: bytes) -> ManagementFrameFrameControl:
        frame_control_bits = getbinary(frame_control[0], 8) + getbinary(frame_control[1], 8)

        return ManagementFrameFrameControl(
            frame_control_bits[6:8],
            frame_control_bits[4:6],
            frame_control_bits[0:4]
        )


class ManagementFrameParser(Parser):

    def parse(self, frame: bytes) -> ManagementFrame:
        radio_tap_header, frame = RadioTapHeaderParser.parse(frame)
        frame_control = ManagementFrameFrameControlParser.parse(frame[0:2])
        duration: str = frame[2:4].hex()
        dest_addr: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[4:10]))
        src_addr: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[10:16]))
        bssid: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[16:22]))
        sequence_control: str = frame[22:24].hex()
        body: str = frame[24: -4].decode(errors="ignore")  # todo fix me, tmp poc
        fcs: str = frame[-4: -1].hex()

        return ManagementFrame(
            radio_tap_header,
            frame_control,
            duration,
            dest_addr,
            src_addr,
            bssid,
            sequence_control,
            body,
            fcs
        )


