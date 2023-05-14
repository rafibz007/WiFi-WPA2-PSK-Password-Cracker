from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter, QoSDataFrameFilter, \
    LogicalLinkControlAuthenticationFilter
from core.parser import RawDataParser
from core.sniffer import PacketSniffer

iface = "wlp4s0mon"

packet_sniffer = PacketSniffer(
    iface,
    RawDataParser(),
    FilterAggregate(
        RadioTapHeaderFilter(),
        DataFrameFilter(),
        QoSDataFrameFilter(),
        LogicalLinkControlAuthenticationFilter(),
    )
)

for packet in packet_sniffer.listen():
    print(packet)
