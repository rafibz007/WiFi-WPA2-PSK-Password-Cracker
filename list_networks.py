from threading import Thread

from core.filters import *
from core.frame import ManagementFrame, ManagementFrameBody
from core.sniffer import PacketSniffer
from core.parser import ManagementFrameParser
from utils.interface import alternate_channels

iface = "wlp4s0mon"

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

# todo send probe request when changing channels

thread = Thread(target=alternate_channels, args=(iface,), daemon=True)
thread.start()

found_aps = {}

print(f"{'BSSID' : >20} | {'CHANNEL' :^8} | {'SSID' : <30}")
print(f"{'':->20}-+-{'':-^8}-+-{'':-<30}")
for packet in packet_sniffer.listen():
    packet: ManagementFrame
    if packet.body.info_elements[ManagementFrameBody.SSID][1] not in found_aps:
        found_aps[packet.body.info_elements[ManagementFrameBody.SSID][1]] = packet.bssid
        print(f"{packet.bssid : >20} | {packet.body.info_elements[ManagementFrameBody.CURRENT_CHANNEL][1] :^8} | {packet.body.info_elements[ManagementFrameBody.SSID][1] : <30}")
