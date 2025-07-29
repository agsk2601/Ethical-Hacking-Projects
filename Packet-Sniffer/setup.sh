#!/bin/bash

echo "[*] Setting up Scapy Packet Sniffer..."
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Installing dependencies..."
pip install --upgrade pip
pip install scapy colorama

echo "[*] Creating logs directory..."
mkdir -p logs

echo "[*] Setup complete."
