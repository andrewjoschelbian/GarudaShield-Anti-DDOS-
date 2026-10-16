#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GarudaShield AntiDDoS Guard v1 - Deteksi & mitigasi DDoS/flood (sisi pertahanan)
Linux  : mitigasi penuh via iptables (butuh root)
Windows: monitoring + blok via Windows Firewall (butuh admin, opsional)

Cara pakai:
  sudo python3 antiddos.py                    # Linux, threshold default
  sudo python3 antiddos.py -t 150 -b 300      # custom threshold & ban time
  py antiddos.py --no-block                   # Windows / mode pantau saja
"""

import argparse
import ipaddress
import os
import platform
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime

IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "antiddos.log")

# ---------------- log ----------------
def log(msg, alert=False):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {'!! ' if alert else ''}{msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ---------------- baca koneksi ----------------
def hex_to_ip(h):
    if len(h) == 8:  # IPv4 little-endian hex
        b = bytes.fromhex(h)
        return ".".join(str(x) for x in b[::-1])
    return h  # IPv6 biarkan mentah

def read_linux_conns():
    """Ambil jumlah koneksi per IP sumber dari /proc/net/tcp* ."""
    counts = defaultdict(int)
    syn_total = 0
    for proc in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(proc) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    local, remote, st = parts[1], parts[2], parts[3]
                    if st == "03":            # SYN_RECV -> bagian dari handshake
                        syn_total += 1
                    if st not in ("01", "03"):  # hanya ESTABLISHED + SYN_RECV
                        continue
                    try:
                        ip = hex_to_ip(remote.rsplit(":", 1)[0])
                        counts[ip] += 1
                    except Exception:
                        pass
        except FileNotFoundError:
            pass
    return counts, syn_total

def read_windows_conns():
    """Fallback Windows: parse netstat -n ."""
    counts = defaultdict(int)
    syn_total = 0
    try:
        out = subprocess.run(["netstat", "-n", "-p", "TCP"],
                             capture_output=True, text=True, timeout=15).stdout
        for line in out.splitlines():
            p = line.split()
            if len(p) >= 4 and p[0] == "TCP":
                state = p[-1]
                if state == "SYN_RECEIVED":
                    syn_total += 1
                if state in ("SYN_RECEIVED", "ESTABLISHED"):
                    try:
                        ip = p[2].rsplit(":", 1)[0].strip("[]")
                        counts[ip] += 1
                    except Exception:
                        pass
    except Exception as e:
        log(f"gagal baca netstat: {e}")
    return counts, syn_total

# ---------------- firewall ----------------
def block_ip(ip):
    if IS_LINUX:
        r = subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"],
                           capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()
    if IS_WINDOWS:
        r = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name=AntiDDoS-BAN-{ip}", "dir=in", "action=block",
             f"remoteip={ip}"],
            capture_output=True, text=True)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    return False, "OS tidak didukung untuk blok otomatis"

def unblock_ip(ip):
    if IS_LINUX:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                       capture_output=True)
    elif IS_WINDOWS:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name=AntiDDoS-BAN-{ip}"],
                       capture_output=True)

# ---------------- util ----------------
def is_whitelisted(ip, whitelist):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    for w in whitelist:
        try:
            if addr in ipaddress.ip_network(w, strict=False):
                return True
        except ValueError:
            pass
    return False

def fmt_top(counts, n=8):
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:n]
    return "  ".join(f"{ip}:{c}" for ip, c in top)

# ---------------- utama ----------------
def main():
    ap = argparse.ArgumentParser(description="AntiDDoS Guard - deteksi & blok IP flood")
    ap.add_argument("-t", "--threshold", type=int, default=100,
                    help="koneksi per IP dalam window -> ban (default 100)")
    ap.add_argument("-w", "--window", type=int, default=10,
                    help="window deteksi detik (default 10)")
    ap.add_argument("-b", "--ban-time", type=int, default=600,
                    help="durasi ban detik, 0 = permanen (default 600)")
    ap.add_argument("-s", "--syn-alert", type=int, default=500,
                    help="total SYN_RECV -> alert flood (default 500)")
    ap.add_argument("--no-block", action="store_true",
                    help="hanya pantau & lapor, jangan blok")
    ap.add_argument("--whitelist", default="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1",
                    help="CIDR yang tak pernah diblok, pisah koma")
    ap.add_argument("-i", "--interval", type=int, default=5,
                    help="interval cek detik (default 5)")
    args = ap.parse_args()

    whitelist = [w.strip() for w in args.whitelist.split(",") if w.strip()]
    mode = "PANTAU-SAJA (no-block)" if args.no_block else \
           ("LINUX/iptables" if IS_LINUX else "WINDOWS/netsh" if IS_WINDOWS else "LAPOR-SAJA")

    print("=" * 60)
    print("  GarudaShield AntiDDoS Guard v1")
    print(f"  OS              : {platform.system()}")
    print(f"  Mode            : {mode}")
    print(f"  Threshold       : {args.threshold} koneksi / {args.window}s per IP")
    print(f"  SYN flood alert : > {args.syn_alert} SYN_RECV")
    print(f"  Ban time        : {'permanen' if args.ban_time == 0 else str(args.ban_time) + 's'}")
    print(f"  Log             : {LOG_FILE}")
    print("=" * 60)
    print("  Ctrl+C untuk berhenti (IP yang diblok otomatis di-unban)")
    print("=" * 60)

    if args.no_block:
        pass
    elif IS_LINUX and os.geteuid() != 0:
        log("PERINGATAN: bukan root -> tidak bisa jalankan iptables, mode pantau-saja")
        args.no_block = True
    elif IS_WINDOWS and not _is_admin_windows():
        log("PERINGATAN: bukan admin -> tidak bisa blok firewall, mode pantau-saja")
        args.no_block = True

    reader = read_linux_conns if IS_LINUX else read_windows_conns
    banned = {}            # ip -> timestamp ban
    window_counts = defaultdict(list)   # ip -> [timestamp]

    log("AntiDDoS Guard mulai")
    try:
        while True:
            counts, syn_total = reader()
            now = time.time()

            # bersihkan window
            for ip in list(window_counts):
                window_counts[ip] = [t for t in window_counts[ip]
                                     if now - t <= args.window]
                if not window_counts[ip]:
                    del window_counts[ip]

            # akumulasi
            for ip, c in counts.items():
                window_counts[ip].extend([now] * c)

            # alert syn flood global
            if syn_total > args.syn_alert:
                log(f"ALERT: {syn_total} SYN_RECV aktif - indikasi SYN FLOOD!", alert=True)

            # deteksi & ban
            for ip, ts in list(window_counts.items()):
                if len(ts) < args.threshold:
                    continue
                if is_whitelisted(ip, whitelist):
                    continue
                if ip in banned:
                    continue
                msg = f"BAN {ip}: {len(ts)} koneksi/{args.window}s"
                if args.no_block:
                    log("DETEKSI " + msg, alert=True)
                else:
                    ok, err = block_ip(ip)
                    if ok:
                        banned[ip] = now
                        log(msg + " -> DIBLOKIR", alert=True)
                    else:
                        log(f"GAGAL blok {ip}: {err}")
                del window_counts[ip]

            # unban
            if args.ban_time > 0:
                for ip, t in list(banned.items()):
                    if now - t >= args.ban_time:
                        unblock_ip(ip)
                        del banned[ip]
                        log(f"UNBAN {ip} setelah {args.ban_time}s")

            # status bar
            top = fmt_top(counts)
            print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
                  f"IP aktif: {len(counts):4d}  SYN_RECV: {syn_total:4d}  "
                  f"banned: {len(banned):3d}  | {top[:60]:60s}", end="", flush=True)

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nBerhenti. Membersihkan semua blok...")
        for ip in list(banned):
            unblock_ip(ip)
            log(f"UNBAN {ip} (shutdown)")
        log("AntiDDoS Guard berhenti")

def _is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if __name__ == "__main__":
    main()
