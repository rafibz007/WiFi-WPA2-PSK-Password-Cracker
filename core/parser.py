from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Tuple, Dict, Any

from core.frame import EthernetFrame, Frame, RawFrame, ManagementFrame, ManagementFrameRadioTapHeader, \
    FrameControl, ManagementFrameBody, DataFrame, QoSDataFrameLogicalLinkControl, EAPOLHandshakeKeyInfo, \
    EAPOLHandshakeNumber, EAPOLHandshakeFrame


# todo Introcude hieriarchy to parsers and prevent code deduplication

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
        # present_flags = frame[4:16]
        # mac_timestamp = frame[16:24]
        # flags = frame[24]
        # data_rate = frame[25]
        channel_frequency = int.from_bytes(frame[26:28], "little")
        return ManagementFrameRadioTapHeader(
            version, pad, header_length, channel_frequency
        ), frame[header_length:]


getbinary = lambda x, n: format(x, 'b').zfill(n)


class FrameControlParser:

    @staticmethod
    def parse(frame_control: bytes) -> FrameControl:
        frame_control_bits = getbinary(frame_control[0], 8) + getbinary(frame_control[1], 8)

        return FrameControl(
            frame_control_bits[6:8],
            frame_control_bits[4:6],
            frame_control_bits[0:4]
        )


class ManagementFrameBodyParser:
    SUPPORTED_IDS = {
        ManagementFrameBody.SSID: lambda ssid: ssid.decode(errors="ignore"),
        ManagementFrameBody.CURRENT_CHANNEL: lambda curr_channel: str(int.from_bytes(curr_channel, "little")),
    }

    @staticmethod
    def parse(body: bytes) -> ManagementFrameBody:
        fixed_fields = body[:12]
        body = body[12:]

        info_elements: Dict[int: Tuple[int, str]] = defaultdict(lambda: (0, "N/A"))
        while len(body) > 0:

            element_id: int = body[0]
            length: int = body[1]

            if element_id in ManagementFrameBodyParser.SUPPORTED_IDS:
                value = ManagementFrameBodyParser.SUPPORTED_IDS[element_id](body[2:2 + length])
                info_elements[element_id] = (length, value)

            body = body[2 + length:]

        return ManagementFrameBody(info_elements, fixed_fields)


class ManagementFrameParser(Parser):

    def parse(self, frame: bytes) -> ManagementFrame:
        radio_tap_header, frame = RadioTapHeaderParser.parse(frame)
        frame_control = FrameControlParser.parse(frame[0:2])
        duration: str = frame[2:4].hex()
        dest_addr: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[4:10]))
        src_addr: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[10:16]))
        bssid: str = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[16:22]))
        sequence_control: str = frame[22:24].hex()
        body: ManagementFrameBody = ManagementFrameBodyParser.parse(frame[24: -4])
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


class QoSDataFrameLogicalLinkControlParser:

    @staticmethod
    def parse(llc: bytes) -> QoSDataFrameLogicalLinkControl:
        return QoSDataFrameLogicalLinkControl(
            str(llc[0]),
            str(llc[1]),
            str(llc[2]),
            llc[3:6].hex(),
            llc[6:8].hex()
        )


class DataFrameParser(Parser):
    def parse(self, frame: bytes) -> Frame:
        radio_tap_header, frame = RadioTapHeaderParser.parse(frame)
        frame_control = FrameControlParser.parse(frame[0:2])
        duration: str = frame[2:4].hex()

        # todo need to specify this to subtype and parse then
        # todo FIRST DETERMINE WHICH SUBTYPE CAN BE USED TO CHECK WETHER USER IS CONNECTED
        # TODO THEN FILTER CORRECTLY
        dest_addr = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[4:10]))
        bssid = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[10:16]))
        source_addr = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[16:22]))
        frame_number_and_sequence = frame[22:24].hex()
        tkip_params = frame[24:32].hex()
        data = frame[50:-4].hex()
        check_sequence = frame[-4:-1].hex()

        return DataFrame(
            radio_tap_header,
            frame_control,
            duration,
            dest_addr,
            bssid,
            source_addr,
            frame_number_and_sequence,
            tkip_params,
            data,
            check_sequence,
        )


class EAPOLHandshakeKeyInfoParser:

    @staticmethod
    def parse(key_info: bytes) -> EAPOLHandshakeKeyInfo:

        key_info_bits: str = getbinary(key_info[0], 8) + getbinary(key_info[1], 8)
        return EAPOLHandshakeKeyInfo(
            key_info_bits[13:16],
            int(key_info_bits[12]),
            key_info_bits[10:12],
            int(key_info_bits[9]),
            int(key_info_bits[8]),
            int(key_info_bits[7]),
            int(key_info_bits[6]),
            int(key_info_bits[5]),
            int(key_info_bits[4]),
            int(key_info_bits[3]),
            int(key_info_bits[2]),
        )


class EAPOLHandshakeFrameParser(Parser):

    M1_KEY_INFO = "..00000010001010"
    M2_KEY_INFO = "..00000100001010"
    M3_KEY_INFO = "..01001111001010"
    M4_KEY_INFO = "..00001100001010"

    def parse(self, frame: bytes) -> Frame:
        radio_tap_header, frame = RadioTapHeaderParser.parse(frame)
        frame_control = FrameControlParser.parse(frame[0:2])
        duration: str = frame[2:4].hex()

        dest_addr = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[4:10]))
        bssid = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[10:16]))
        source_addr = ":".join(map(lambda byte: hex(byte).lstrip("0x").zfill(2), frame[16:22]))
        frame_number_and_sequence = frame[22:24].hex()
        qos_control = frame[24:26].hex()

        check_sequence = frame[-4:-1].hex()

        llc = QoSDataFrameLogicalLinkControlParser.parse(frame[26:34])

        # 802.1x
        version = hex(frame[34])
        key_type = hex(frame[35])
        length = int.from_bytes(frame[36:38], "big")

        key_details_bytes = frame[38:38+length]

        key_descriptor_type = hex(key_details_bytes[0])
        key_info = EAPOLHandshakeKeyInfoParser.parse(key_details_bytes[1:3])

        key_length = int.from_bytes(key_details_bytes[3:5], "big")
        replay_counter = int.from_bytes(key_details_bytes[5:13], "big")

        # todo those values may differ when we take key_length into considerations
        wpa_key_nonce = key_details_bytes[13:45].hex()
        key_iv = key_details_bytes[45:61].hex()
        key_rsc = key_details_bytes[61:69].hex()
        key_id = key_details_bytes[69:77].hex()
        key_mic = key_details_bytes[77:93].hex()
        key_data_length = int.from_bytes(key_details_bytes[93:95], "big")
        key_data = key_details_bytes[95:95+key_data_length].hex()

        if key_info.full() == self.M1_KEY_INFO:
            message = EAPOLHandshakeNumber.M1
        elif key_info.full() == self.M2_KEY_INFO:
            message = EAPOLHandshakeNumber.M2
        elif key_info.full() == self.M3_KEY_INFO:
            message = EAPOLHandshakeNumber.M3
        elif key_info.full() == self.M4_KEY_INFO:
            message = EAPOLHandshakeNumber.M4
        else:
            message = None
            raise RuntimeWarning("Unrecognised KeyInfo. Skipping packet")

        return EAPOLHandshakeFrame(
            message,
            version,
            key_type,
            length,
            key_descriptor_type,
            key_info,
            key_length,
            replay_counter,
            wpa_key_nonce,
            key_iv,
            key_rsc,
            key_id,
            key_mic,
            key_data_length,
            key_data
        )
