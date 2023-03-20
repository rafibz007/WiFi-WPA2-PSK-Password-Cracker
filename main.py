import socket

from core.filters import ManagementFrameFilter
from core.sniffer import PacketSniffer
from utils.interface import *
from core.parser import EthernetParser, RawDataParser, ManagementFrameParser

iface = "wlp4s0mon"

ETH_P_ALL = 0x0003

packet_sniffer = PacketSniffer(
    iface,
    ManagementFrameParser(),
    ManagementFrameFilter()
)


for packet in packet_sniffer.listen():
    print(packet)
