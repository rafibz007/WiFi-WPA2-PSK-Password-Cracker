import os


def turn_on_monitor_mode(iface: str):
    # os.system(f"sudo ifconfig {iface} down")
    # os.system(f"sudo iwconfig {iface} mode monitor")
    # os.system(f"sudo ifconfig {iface} up")
    os.system(f"sudo airmon-ng check kill")
    os.system(f"sudo airmon-ng start {iface}")


def turn_off_monitor_mode(iface: str):
    # os.system(f"sudo ifconfig {iface} down")
    # os.system(f"sudo iwconfig {iface} mode managed")
    # os.system(f"sudo ifconfig {iface} up")
    os.system(f"sudo airmon-ng stop {iface}")


def change_channel(iface: str, channel: int):
    os.system(f"sudo iwconfig {iface} channel {channel}")