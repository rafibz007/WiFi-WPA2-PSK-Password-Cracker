import socket

from core.filters import *
from core.sniffer import PacketSniffer
from utils.interface import *
from core.parser import EthernetParser, RawDataParser, ManagementFrameParser

iface = "wlp4s0mon"

ETH_P_ALL = 0x0003

packet_sniffer = PacketSniffer(
    iface,
    ManagementFrameParser(),
    FilterAggregate(
        RadioTapHeaderFilter(),
        ManagementFrameFilter(),
        FilterAlternative(
            BeaconFrameFilter(),
            ProbeResponseFrameFilter()
        )
    )
)

# ssid listing
# in second thread change channels and send probe requests (another interface may be neccessary)
# here receive filtered and parsed probe responses and beacon frames
for packet in packet_sniffer.listen():
    print(packet)

# 4-way handshake grabing
# listen for authed users then
# in second thread send deauth requests
# here receive all filtered 4-way handshake requests then start password cracking
# todo
