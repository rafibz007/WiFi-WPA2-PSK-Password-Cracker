from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter, QoSDataFrameFilter, \
    LogicalLinkControlAuthenticationFilter, AuthenticationKeyTypeFilter, CRC32Filter, DataFrameBssidFilter
from core.frame import EAPOLHandshakeFrame
from core.parser import RawDataParser, EAPOLHandshakeFrameParser
from core.sniffer import PacketSniffer

# random mac from android hot spot
bssid = "a2:cf:2d:38:59:0c"
iface = "wlp4s0mon"

packet_sniffer = PacketSniffer(
    iface,
    EAPOLHandshakeFrameParser(),
    FilterAggregate(
        CRC32Filter(),
        RadioTapHeaderFilter(),
        DataFrameFilter(),
        DataFrameBssidFilter(bssid),
        QoSDataFrameFilter(),
        LogicalLinkControlAuthenticationFilter(),
        AuthenticationKeyTypeFilter()
    )
)

captured_handshakes = {}

for packet in packet_sniffer.listen():
    packet: EAPOLHandshakeFrame

    # HACK - wrong packet parsing
    supplicant_ssid = packet.dest_addr if packet.dest_addr != bssid else packet.bssid
    print(f"Captured {packet.message_number} frame from supplicant {supplicant_ssid}")

    if supplicant_ssid not in captured_handshakes:
        captured_handshakes[supplicant_ssid] = {}

    captured_handshakes[supplicant_ssid][packet.message_number] = packet

    if len(captured_handshakes[supplicant_ssid]) == 4:
        print(f"Captured 4 packets from {supplicant_ssid}. Starting password cracking.")
        break

