from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter
from core.parser import DataFrameParser
from core.sniffer import PacketSniffer

iface = "wlp4s0mon"

packet_sniffer = PacketSniffer(
    iface,
    DataFrameParser(),
    FilterAggregate(
        RadioTapHeaderFilter(),
        DataFrameFilter()
    )
)

for packet in packet_sniffer.listen():
    print(packet)
