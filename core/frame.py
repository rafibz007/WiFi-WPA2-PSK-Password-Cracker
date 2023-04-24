from abc import ABC
from typing import Dict, Tuple


class Frame(ABC):
    ...


class EthernetFrame(Frame):
    def __init__(self, src: str, dst: str, type_len: str, data: str, crc: str):
        self.src: str = src
        self.dst: str = dst
        self.type_len: str = type_len
        self.data: str = data
        self.crc: str = crc

    def to_bytes(self):
        ...

    def __str__(self):
        return f"Ethernet: {{ dst = {self.dst}, src = {self.src}, type/len = {self.type_len}, data = {self.data}, crc = {self.crc} }}"


class RawFrame(Frame):
    def __init__(self, raw_data: bytes):
        self.raw_data = raw_data

    def __str__(self):
        return str(self.raw_data)


class ManagementFrameFrameControl:
    def __init__(
            self,
            proto_version: str,
            frame_type: str,
            frame_subtype: str,
            # to_ds: str,
            # from_ds: str,
            # more_fragments: str,
            # retry: str,
            # power_management: str,
            # more_data: str,
            # protected_frame: str,
            # htc_order: str
    ):
        self.proto_version: str = proto_version
        self.frame_type: str = frame_type
        self.frame_subtype: str = frame_subtype
        # self.to_ds: str = to_ds
        # self.from_ds: str = from_ds
        # self.more_fragments: str = more_fragments
        # self.retry: str = retry
        # self.power_management: str = power_management
        # self.more_data: str = more_data
        # self.protected_frame: str = protected_frame
        # self.htc_order: str = htc_order

    def __str__(self):
        return f"FrameControl: {{ proto_version = {self.proto_version}, " \
               f"type = {self.frame_type}, " \
               f"subtype = {self.frame_subtype}" \
               f" }}"


class ManagementFrameRadioTapHeader:
    def __init__(self, version: str, pad: str, header_len: int, channel_frequency: int):
        self.version: str = version
        self.pad: str = pad
        self.header_len: int = header_len
        self.channel_frequency: int = channel_frequency


class ManagementFrameBody:
    SSID = 0
    CURRENT_CHANNEL = 3

    def __init__(self, info_elements, fixed_fields: bytes):
        self.fixed_fields: bytes = fixed_fields
        self.info_elements: Dict[int: Tuple[int, str]] = info_elements  # id -> len, value

    def __str__(self):
        return f"Body: {{ {';'.join([ f'id={id}, len={len_and_value[0]}, value={len_and_value[1]} ' for id, len_and_value in self.info_elements.items() ])} }}"


class ManagementFrame:
    def __init__(
            self,
            radio_tap_header: ManagementFrameRadioTapHeader,
            frame_control: ManagementFrameFrameControl,
            duration: str,
            dest_addr: str,
            src_addr: str,
            bssid: str,
            sequence_control: str,
            body: ManagementFrameBody,
            fcs: str
    ):
        self.radio_tap_header: ManagementFrameRadioTapHeader = radio_tap_header
        self.frame_control: ManagementFrameFrameControl = frame_control
        self.duration: str = duration
        self.dest_addr: str = dest_addr
        self.src_addr: str = src_addr
        self.bssid: str = bssid
        self.sequence_control: str = sequence_control
        self.body: ManagementFrameBody = body
        self.fcs: str = fcs

    def __str__(self):
        return f"Management: {{ " \
               f"frame control = {self.frame_control},  " \
               f"duration = {self.duration}, " \
               f"dest addr = {self.dest_addr}, " \
               f"src addr = {self.src_addr}, " \
               f"bssid = {self.bssid}, " \
               f"sequence control = {self.sequence_control}, " \
               f"body = {self.body}, " \
               f"fcs = {self.fcs}" \
               f"}}"


