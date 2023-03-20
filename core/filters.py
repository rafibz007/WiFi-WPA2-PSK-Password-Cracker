from abc import ABC, abstractmethod
from typing import List


getbinary = lambda x, n: format(x, 'b').zfill(n)


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
        frame_control = frame[0:2]
        frame_control_str = getbinary(frame_control[0], 8) + getbinary(frame_control[1], 8)

        proto_version = frame_control_str[0:2]
        frame_type = frame_control_str[2:4]
        frame_subtype = frame_control_str[4:7]

        return proto_version == "00" and frame_type == "00"
