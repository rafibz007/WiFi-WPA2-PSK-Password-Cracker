from abc import ABC
from typing import Dict


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


class ManagementFrame:
    ...