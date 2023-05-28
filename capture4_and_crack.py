from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter, QoSDataFrameFilter, \
    LogicalLinkControlAuthenticationFilter, AuthenticationKeyTypeFilter, CRC32Filter
from core.parser import RawDataParser, EAPOLHandshakeFrameParser
from core.sniffer import PacketSniffer

iface = "wlp4s0mon"

packet_sniffer = PacketSniffer(
    iface,
    EAPOLHandshakeFrameParser(),
    FilterAggregate(
        CRC32Filter(),
        RadioTapHeaderFilter(),
        DataFrameFilter(),
        # add filter for bssid
        QoSDataFrameFilter(),
        LogicalLinkControlAuthenticationFilter(),
        AuthenticationKeyTypeFilter()
    )
)

captured_handshakes = {}

for packet in packet_sniffer.listen():
    print(packet)
