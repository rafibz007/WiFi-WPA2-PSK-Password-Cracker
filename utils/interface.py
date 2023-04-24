import os
from itertools import cycle
from time import sleep


def change_channel(iface: str, channel: int):
    os.system(f"sudo iwconfig {iface} channel {channel}")


def alternate_channels(iface: str):
    for i in cycle([1, 3, 5, 9, 10, 11, 12, 13, 36, 40]):
        change_channel(iface, i)
        sleep(0.1)
