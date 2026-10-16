# AntiDDoS Guard v1

Tool pertahanan untuk **mendeteksi dan memblokir serangan DDoS/flood** pada server.
Ditulis dalam **Bahasa Indonesia**, tanpa dependensi eksternal (murni Python standard library).

**Dibuat oleh: [@andrewjoschelbian](https://github.com/andrewjoschelbian)**

---

## Tentang

AntiDDoS Guard memantau koneksi masuk ke server secara real-time, mendeteksi pola
flood (koneksi berlebihan dari satu IP atau gelombang SYN flood), lalu memblokir
IP penyerang secara otomatis melalui firewall — dan membukanya lagi (unban)
setelah durasi tertentu.

| Aspek | Keterangan |
|-------|-----------|
| **Platform** | Linux (mitigasi penuh via iptables) dan Windows (via Windows Firewall) |
| **Bahasa** | Indonesia (tampilan terminal dan log) |
| **Dependensi** | Tidak ada — hanya Python 3 standard library |
| **Mode** | Blok otomatis / pantau-saja (`--no-block`) |

## Fitur

- **Deteksi IP flood** — IP dengan koneksi melewati threshold dalam window waktu
  tertentu otomatis diblokir (default: lebih dari 100 koneksi / 10 detik).
- **Deteksi SYN flood** — memantau jumlah `SYN_RECV`; melewati batas (default 500)
  langsung muncul alert.
- **Blok otomatis via firewall**
  - Linux: `iptables -I INPUT -s <IP> -j DROP`
  - Windows: rule block pada Windows Firewall (perlu Administrator)
- **Unban otomatis** — IP dibuka kembali setelah durasi ban berakhir
  (default 600 detik), dan semua blok dibersihkan saat tool dihentikan (Ctrl+C).
- **Whitelist bawaan** — loopback dan jaringan privat
  (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`)
  tidak akan pernah diblokir.
- **Log ke file** — semua kejadian (ban, unban, alert, error) tercatat di
  `antiddos.log` di folder yang sama dengan script.
- **Mode pantau-saja** — cukup memantau dan melapor tanpa memblokir apa pun.

## Persyaratan

- **Python 3.7+** (tanpa library tambahan)
- Linux: jalankan sebagai **root** (agar bisa menjalankan `iptables`)
- Windows: jalankan **CMD/PowerShell sebagai Administrator**
  (agar bisa menjalankan `netsh advfirewall`)

Cek versi Python:

```bash
python3 --version     # Linux
py --version          # Windows
```

## Cara Menggunakan

### Linux

```bash
# Jalankan dengan pengaturan default (perlu root)
sudo python3 antiddos.py

# Threshold lebih ketat, ban selama 5 menit
sudo python3 antiddos.py -t 50 -b 300

# Hanya memantau tanpa memblokir (aman untuk dicoba dulu)
python3 antiddos.py --no-block
```

### Windows

```powershell
# Jalankan PowerShell/CMD sebagai Administrator, lalu:
py antiddos.py

# Mode pantau-saja (tidak perlu admin)
py antiddos.py --no-block
```

Saat berjalan, tool menampilkan status bar real-time: jumlah IP aktif,
jumlah `SYN_RECV`, jumlah IP yang sedang diblok, dan IP dengan koneksi terbanyak.
Tekan **Ctrl+C** untuk berhenti — semua blok yang aktif akan otomatis dibuka.

## Parameter

| Parameter | Default | Keterangan |
|-----------|---------|------------|
| `-t`, `--threshold` | 100 | Jumlah koneksi per IP dalam window untuk dianggap flood |
| `-w`, `--window` | 10 | Window deteksi dalam detik |
| `-b`, `--ban-time` | 600 | Durasi ban dalam detik (`0` = permanen) |
| `-s`, `--syn-alert` | 500 | Alert jika total `SYN_RECV` melewati angka ini |
| `-i`, `--interval` | 5 | Interval pengecekan dalam detik |
| `--no-block` | - | Hanya memantau, tidak memblokir |
| `--whitelist` | (lihat bawaan) | Daftar CIDR yang dikecualikan dari blokir, dipisah koma |

Contoh menambahkan IP sendiri ke whitelist:

```bash
sudo python3 antiddos.py --whitelist "127.0.0.0/8,192.168.0.0/16,203.0.113.10"
```

## Cara Kerja Singkat

1. Setiap `--interval` detik, tool membaca daftar koneksi TCP masuk
   (Linux: `/proc/net/tcp`, Windows: `netstat -n`).
2. Koneksi dihitung per IP sumber dalam window `--window` detik terakhir.
3. IP yang melewati `--threshold` dan tidak masuk whitelist → diblokir firewall.
4. Blokir dicabut otomatis setelah `--ban-time` detik, atau saat tool dihentikan.
5. Semua kejadian dicatat di terminal dan `antiddos.log`.

## Tips Penyetelan

1. Jalankan `--no-block` selama beberapa menit saat server normal.
   Perhatikan angka koneksi per IP di status bar.
2. Atur `-t` sedikit **di atas** angka normal tersebut, misalnya normal 80
   koneksi → pakai `-t 150`.
3. Untuk server dengan trafik tinggi (banyak pengguna NAT), naikkan window `-w`
   agar tidak salah blokir pengguna sah.
4. Tambahkan IP tetap (kantor, monitoring) ke `--whitelist`.

## Keterbatasan & Rekomendasi

- Tool ini adalah **pertahanan lapis dasar** untuk server kecil/VPS. Untuk
  serangan berskala besar (puluhan Gbps), tambahkan mitigasi di level jaringan:
  - `fail2ban` untuk pola serangan berulang
  - Rate limiting di nginx/Apache
  - SYN cookies: `net.ipv4.tcp_syncookies=1` (sysctl)
  - Layanan proteksi seperti Cloudflare
- Tidak menganalisis isi paket (payload) — hanya berbasis jumlah koneksi.

## Log Contoh

```
[2026-10-16 21:40:11] AntiDDoS Guard mulai
[2026-10-16 21:41:02] !! ALERT: 612 SYN_RECV aktif - indikasi SYN FLOOD!
[2026-10-16 21:41:02] !! BAN 203.0.113.77: 214 koneksi/10s -> DIBLOKIR
[2026-10-16 21:51:02] UNBAN 203.0.113.77 setelah 600s
```

## Disclaimer

Tool ini dibuat untuk **mempertahankan server sendiri** dari serangan flood.
Gunakan hanya pada infrastruktur yang Anda miliki atau kelola. Penyalahgunaan
merupakan tanggung jawab pengguna sepenuhnya.

---

Dibuat oleh **[@andrewjoschelbian](https://github.com/andrewjoschelbian)** —
Bahasa Indonesia, open source.
