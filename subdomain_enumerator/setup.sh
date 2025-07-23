#!/bin/bash

echo "Starting up subdomain Enumerator.."
python3 -m venv .venv

echo "Activate python Environment.."
source .venv/bin/activate
echo "python Environment Activated.."

pip install --upgrade pip

echo "Installing requirements..."
pip install -r requirements.txt

echo "downloading wordlist...."
curl -L https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -o wordlists/subdomains.txt

echo "setup complete"
