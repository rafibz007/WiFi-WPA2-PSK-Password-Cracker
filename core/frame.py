from abc import ABC
from enum import Enum
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


class FrameControl:
    def __init__(
            self,
            proto_version: str,
            frame_type: str,
            frame_subtype: str,
    ):
        self.proto_version: str = proto_version
        self.frame_type: str = frame_type
        self.frame_subtype: str = frame_subtype

    def full(self):
        return self.frame_subtype + self.frame_type + self.proto_version

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
        return f"Body: {{ {';'.join([f'id={id}, len={len_and_value[0]}, value={len_and_value[1]} ' for id, len_and_value in self.info_elements.items()])} }}"


class ManagementFrame(Frame):
    def __init__(
            self,
            radio_tap_header: ManagementFrameRadioTapHeader,
            frame_control: FrameControl,
            duration: str,
            dest_addr: str,
            src_addr: str,
            bssid: str,
            sequence_control: str,
            body: ManagementFrameBody,
            fcs: str
    ):
        self.radio_tap_header: ManagementFrameRadioTapHeader = radio_tap_header
        self.frame_control: FrameControl = frame_control
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


class QoSDataFrameLogicalLinkControl:
    def __init__(self, dsap: str, ssap: str, control_field: str, org_code: str, llc_type: str):
        self.dsap: str = dsap
        self.ssap: str = ssap
        self.control_field: str = control_field
        self.org_code: str = org_code
        self.llc_type: str = llc_type


class DataFrame(Frame):
    def __init__(
            self,
            radio_tap_header: ManagementFrameRadioTapHeader,
            frame_control: FrameControl,
            duration: str,
            dest_addr: str,
            bssid: str,
            source_addr: str,
            frame_number_and_sequence: str,
            tkip_params: str,
            data: str,
            check_sequence: str,
    ):
        self.radio_tap_header: ManagementFrameRadioTapHeader = radio_tap_header
        self.frame_control: FrameControl = frame_control
        self.duration: str = duration
        self.dest_addr: str = dest_addr
        self.bssid: str = bssid
        self.source_addr: str = source_addr
        self.frame_number_and_sequence: str = frame_number_and_sequence
        self.tkip_params: str = tkip_params
        self.data: str = data
        self.check_sequence: str = check_sequence

    def __str__(self):
        return f"Data: {{ " \
               f"frame control = {self.frame_control},  " \
               f"duration = {self.duration}, " \
               f"dest addr = {self.dest_addr}, " \
               f"bssid = {self.bssid}, " \
               f"src addr = {self.source_addr}, " \
               f"frame number and sequence = {self.frame_number_and_sequence}, " \
               f"TKIP = {self.tkip_params}, " \
               f"}}"


class EAPOLHandshakeNumber(Enum):
    M1 = 1
    M2 = 2
    M3 = 3
    M4 = 4


class EAPOLHandshakeKeyInfo:
    def __init__(
            self,
            key_descriptor_version: str,
            key_type: int,
            key_index: str,
            install: int,
            key_ack: int,
            key_mic: int,
            secure: int,
            error: int,
            request: int,
            encrypted_key_data: int,
            smk_message: int,
    ):
        self.key_descriptor_version: str = key_descriptor_version
        self.key_type: int = key_type
        self.key_index: str = key_index
        self.install: int = install
        self.key_ack: int = key_ack
        self.key_mic: int = key_mic
        self.secure: int = secure
        self.error: int = error
        self.request: int = request
        self.encrypted_key_data: int = encrypted_key_data
        self.smk_message: int = smk_message

    def full(self) -> str:
        return f"..{self.smk_message}{self.encrypted_key_data}{self.request}{self.error}{self.secure}{self.key_mic}{self.key_ack}{self.install}{self.key_index}{self.key_type}{self.key_descriptor_version}"

    def __str__(self):
        return self.full()


class EAPOLHandshakeFrame(Frame):
    def __init__(
            self,
            dest_addr: str,
            bssid: str,
            src_addr: str,
            message_number: EAPOLHandshakeNumber,
            version: str,
            key_type: str,
            length: int,
            key_descriptor_type: str,
            key_info: EAPOLHandshakeKeyInfo,
            key_length: int,
            replay_counter: int,
            wpa_key_nonce: str,
            key_iv: str,
            key_rsc: str,
            key_id: str,
            key_mic: str,
            key_data_length: int,
            key_data: str,
    ):
        self.dest_addr: str = dest_addr
        self.bssid: str = bssid
        self.src_addr: str = src_addr
        self.message_number: EAPOLHandshakeNumber = message_number
        self.version: str = version
        self.key_type: str = key_type
        self.length: int = length
        self.key_descriptor_type: str = key_descriptor_type
        self.key_info: EAPOLHandshakeKeyInfo = key_info
        self.key_length: int = key_length
        self.replay_counter: int = replay_counter
        self.wpa_key_nonce: str = wpa_key_nonce
        self.key_iv: str = key_iv
        self.key_rsc: str = key_rsc
        self.key_id: str = key_id
        self.key_mic: str = key_mic
        self.key_data_length: int = key_data_length
        self.key_data: str = key_data

    def __str__(self):
        return f"EAPOLHandshake M{self.message_number} = {{ " \
               f"version = {self.version} " \
               f"key type = {self.key_type} " \
               f"length = {self.length} " \
               f"key description type = {self.key_descriptor_type} " \
               f"key info = {self.key_info} " \
               f"key length = {self.key_length} " \
               f"replay counter = {self.replay_counter} " \
               f"wpa key nonce = {self.wpa_key_nonce} " \
               f"key IV = {self.key_iv} " \
               f"key rsc = {self.key_rsc} " \
               f"key id = {self.key_id} " \
               f"key MIC = {self.key_mic} " \
               f"key data length = {self.key_data_length} " \
               f"key data = {self.key_data} " \
               f"}}"


class DeauthenticationFrame(Frame):
    def __init__(self, bssid: str, dest_addr: str = "ff:ff:ff:ff:ff:ff"):
        self.frame_control = FrameControl("00", "00", "1100")
        self.flags = "00"
        self.duration = "3a01"
        self.dest_addr = dest_addr
        self.src_addr = bssid
        self.bssid = bssid
        self.frame_number_sequence = "0000"
        self.fixed_params = "0700"

    def to_bytes(self):
        frame_control = hex(int(self.frame_control.full(), 2)).lstrip("0x").zfill(2)
        bssid = "".join(self.bssid.lower().split(":"))
        src_addr = "".join(self.src_addr.lower().split(":"))
        dest_addr = "".join(self.dest_addr.lower().split(":"))

        data = "".join([frame_control, self.flags, self.duration, dest_addr, src_addr, bssid,
                        self.frame_number_sequence, self.fixed_params])

        return bytes.fromhex(data)
