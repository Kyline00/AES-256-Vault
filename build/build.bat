@echo off
REM 在项目根目录执行: build\build.bat
cd /d "%~dp0"
if not exist "..\aes256_vault.py" (
    echo Error: aes256_vault.py not found in parent directory.
    exit /b 1
)
pip install pyinstaller -q
pyinstaller aes256vault.spec
echo.
echo Output: dist\AES256Vault.exe
