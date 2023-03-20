import socket

from core.filters import ManagementFrameFilter
from core.sniffer import PacketSniffer
from utils.interface import *
from core.parser import EthernetParser, RawDataParser

iface = "wlp4s0"

ETH_P_ALL = 0x0003

packet_sniffer = PacketSniffer(
    iface,
    RawDataParser(),
    # ManagementFrameFilter()
)

try:
    turn_on_monitor_mode(iface)

    for packet in packet_sniffer.listen():
        print(packet)

finally:
    turn_off_monitor_mode(iface)
