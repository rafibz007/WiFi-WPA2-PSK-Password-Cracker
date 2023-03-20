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
        return all(map(lambda _filter: _filter(frame), self._filters))


class AllMatchFilter(Filter):

    def match(self, frame: bytes) -> bool:
        return True


class ManagementFrameFilter(Filter):

    def match(self, frame: bytes) -> bool:
        _, frame = RadioTapHeaderParser.parse(frame)

        frame_control = ManagementFrameFrameControlParser.parse(frame[0:2])

        return frame_control.proto_version == "00" and frame_control.frame_type == "00"

        return False
