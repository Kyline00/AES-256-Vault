#!/bin/bash
# 在虚拟环境中运行 AES-256 Vault
cd "$(dirname "$0")"
if [ ! -f ".venv/bin/activate" ]; then
    echo "正在创建虚拟环境..."
    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt -q
else
    . .venv/bin/activate
fi
python aes256_vault.py
