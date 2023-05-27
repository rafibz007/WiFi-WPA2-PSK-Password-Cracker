from abc import ABC, abstractmethod
from typing import List

from core.parser import RadioTapHeaderParser, FrameControlParser, QoSDataFrameLogicalLinkControlParser
from utils.frames import calculate_crc32


class Filter(ABC):

    @abstractmethod
    def match(self, frame: bytes) -> bool:
        ...


class FilterAggregate(Filter):

    def __init__(self, *args):
        self._filters: List[Filter] = [_filter for _filter in args]

    def match(self, frame: bytes) -> bool:
        return all(map(lambda _filter: _filter.match(frame), self._filters))


class FilterAlternative(Filter):
    def __init__(self, *args):
        self._filters: List[Filter] = [_filter for _filter in args]

    def match(self, frame: bytes) -> bool:
        return any(map(lambda _filter: _filter.match(frame), self._filters))


class AllMatchFilter(Filter):

    def match(self, frame: bytes) -> bool:
        return True


class CRC32Filter(Filter):

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        actual_crc = calculate_crc32(frame[:-4])
        received_crc = frame[-4:]

        return actual_crc == received_crc


class RadioTapHeaderFilter(Filter):

    # expected values
    HEADER_REVISION_HEX = "00"
    HEADER_PAD_HEX = "00"
    HEADER_LENGTH_HEX = "3800"  # not sure if this is relevant to check, but it works

    EXPECTED_FRAME_START_HEX = HEADER_REVISION_HEX + HEADER_PAD_HEX + HEADER_LENGTH_HEX

    def match(self, frame: bytes) -> bool:
        return frame[0:4].hex() == self.EXPECTED_FRAME_START_HEX


class ManagementFrameFilter(Filter):

    PROTO_VERSION = "00"
    MANAGEMENT_FRAME_TYPE = "00"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = FrameControlParser.parse(frame[0:2])

        return frame_control.proto_version == self.PROTO_VERSION \
            and frame_control.frame_type == self.MANAGEMENT_FRAME_TYPE


class BeaconFrameFilter(Filter):

    BEACON_SUBTYPE = "1000"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = FrameControlParser.parse(frame[0:2])

        return frame_control.frame_subtype == self.BEACON_SUBTYPE


class ProbeResponseFrameFilter(Filter):

    PROBE_RESPONSE_SUBTYPE = "0101"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = FrameControlParser.parse(frame[0:2])

        return frame_control.frame_subtype == self.PROBE_RESPONSE_SUBTYPE


class DataFrameFilter(Filter):
    PROTO_VERSION = "00"
    DATA_FRAME_TYPE = "10"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = FrameControlParser.parse(frame[0:2])

        return frame_control.proto_version == self.PROTO_VERSION \
            and frame_control.frame_type == self.DATA_FRAME_TYPE

class QoSDataFrameFilter(Filter):

    QOS_DATA_SUBTYPE = "1000"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = FrameControlParser.parse(frame[0:2])

        return frame_control.frame_subtype == self.QOS_DATA_SUBTYPE


class LogicalLinkControlAuthenticationFilter(Filter):

    LLC_AUTHENTICATION_TYPE = "888e"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        # skip to llc part
        llc = QoSDataFrameLogicalLinkControlParser.parse(frame[26:34])

        return llc.llc_type == self.LLC_AUTHENTICATION_TYPE


class AuthenticationKeyTypeFilter(Filter):

    AUTHENTICATION_KEY_TYPE = "3"
    AUTHENTICATION_KEY_DESCRIPTOR_TYPE = "2"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        # skip to 802.1x part
        frame = frame[34:]

        return hex(frame[1]) == "0x" + self.AUTHENTICATION_KEY_TYPE and hex(frame[4]) == "0x" + self.AUTHENTICATION_KEY_DESCRIPTOR_TYPE
