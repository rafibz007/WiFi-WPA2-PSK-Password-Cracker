import socket
from itertools import cycle
from threading import Thread
from time import sleep

from core.filters import *
from core.frame import ManagementFrame, ManagementFrameBody
from core.sniffer import PacketSniffer
from utils.interface import *
from core.parser import EthernetParser, RawDataParser, ManagementFrameParser

iface = "wlp4s0mon"

def alternate_channels():
    for i in cycle([1, 3, 5, 9, 10, 11, 12, 13, 36, 40]):
        change_channel(iface, i)
        sleep(0.1)


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
# RUNS IN MONITOR MODE
# change_channel()
thread = Thread(target=alternate_channels, args=(), daemon=True)
thread.start()

found_aps = {}

print(f"{'BSSID' : >20} | {'FREQUENCY' :^10} | {'SSID' : <30}")
print(f"{'':->20}-+-{'':-^10}-+-{'':-<30}")
for packet in packet_sniffer.listen():
    # print(packet)
    packet: ManagementFrame
    if packet.body.info_elements[ManagementFrameBody.SSID][1] not in found_aps:
        found_aps[packet.body.info_elements[ManagementFrameBody.SSID][1]] = packet.bssid
        print(f"{packet.bssid : >20} | {packet.radio_tap_header.channel_frequency :^10} | {packet.body.info_elements[ManagementFrameBody.SSID][1] : <30}")

    # packet_sniffer.send()

# 4-way handshake grabing
# listen for authed users then
# in second thread send deauth requests
# here receive all filtered 4-way handshake requests then start password cracking
# todo
