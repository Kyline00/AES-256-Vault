#!/bin/bash
# 在项目根目录执行: ./build/build.sh 或 bash build/build.sh
cd "$(dirname "$0")"
if [ ! -f "../aes256_vault.py" ]; then
    echo "Error: aes256_vault.py not found in parent directory."
    exit 1
fi
pip install pyinstaller -q
pyinstaller aes256vault.spec
echo ""
echo "Output: dist/AES256Vault (or AES256Vault.exe on Windows)"
