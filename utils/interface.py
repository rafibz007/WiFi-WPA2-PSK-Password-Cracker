import os


def turn_on_monitor_mode(iface: str):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode monitor")
    os.system(f"sudo ifconfig {iface} up")


def turn_off_monitor_mode(iface: str):
    os.system(f"sudo ifconfig {iface} down")
    os.system(f"sudo iwconfig {iface} mode managed")
    os.system(f"sudo ifconfig {iface} up")
