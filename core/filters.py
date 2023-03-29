from abc import ABC, abstractmethod
from typing import List

from core.parser import RadioTapHeaderParser, ManagementFrameFrameControlParser


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

        frame_control = ManagementFrameFrameControlParser.parse(frame[0:2])

        return frame_control.proto_version == self.PROTO_VERSION and frame_control.frame_type == self.MANAGEMENT_FRAME_TYPE


class BeaconFrameFilter(Filter):

    BEACON_SUBTYPE = "1000"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = ManagementFrameFrameControlParser.parse(frame[0:2])

        return frame_control.frame_subtype == self.BEACON_SUBTYPE


class ProbeResponseFrameFilter(Filter):

    PROBE_RESPONSE_SUBTYPE = "0101"

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = ManagementFrameFrameControlParser.parse(frame[0:2])

        return frame_control.frame_subtype == self.PROBE_RESPONSE_SUBTYPE
