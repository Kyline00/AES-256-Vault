@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" (
    echo 正在创建虚拟环境...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt -q
) else (
    call .venv\Scripts\activate.bat
)
python aes256_vault.py
pause
