# 在虚拟环境中运行 AES-256 Vault
Set-Location $PSScriptRoot
if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    Write-Host "正在创建虚拟环境..."
    python -m venv .venv
    & .\.venv\Scripts\pip install -r requirements.txt -q
}
& .\.venv\Scripts\Activate.ps1
python aes256_vault.py
