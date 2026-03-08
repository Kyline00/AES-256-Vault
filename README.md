# AES-256 Vault

基于 **AES-256-GCM** 与 **Scrypt** 的本地加密工具，零网络、零上传，适用于个人与企业敏感数据保护。

**项目地址**：[https://github.com/Kyline00/AES-256-Vault](https://github.com/Kyline00/AES-256-Vault)

---

## 特性

| 特性 | 说明 |
|------|------|
| **零网络** | 全部在本地计算，无任何联网或上传 |
| **AEAD 加密** | AES-256-GCM，提供机密性、完整性与真实性 |
| **密钥派生** | Scrypt N=2¹⁷，抗 GPU/ASIC 暴力破解 |
| **密码强度** | 实时显示强度等级（极弱～极强） |
| **.vault 格式** | 加密文件内嵌原始文件名与大小，解密自动还原 |
| **跨平台** | 支持 Windows / macOS / Linux |

---

## 环境要求

- **Python** 3.11 或更高版本
- **tkinter**（通常随 Python 安装；Linux 可安装 `python3-tk`）
- **依赖**：`cryptography==42.0.8`（见 `requirements.txt`）

---

## 快速开始

### 方式一：手动安装

```bash
git clone https://github.com/Kyline00/AES-256-Vault.git
cd AES-256-Vault
python -m venv .venv
.venv\Scripts\activate   # Windows
# source .venv/bin/activate   # Linux / macOS
pip install -r requirements.txt
python aes256_vault.py
```

### 方式二：一键运行脚本（自动创建虚拟环境并安装依赖）

- **Windows**：双击或执行 `run.bat`
- **PowerShell**：`.\run.ps1`
- **Linux / macOS**：`./run.sh`

---

## 项目结构

```
AES-256-Vault/
├── aes256_vault.py      # 主程序（加密逻辑 + GUI）
├── requirements.txt     # Python 依赖
├── README.md            # 本说明文档
├── .gitignore
├── run.bat              # Windows 启动脚本
├── run.ps1              # PowerShell 启动脚本
├── run.sh               # Linux/macOS 启动脚本
├── tests/               # 单元测试
│   ├── test_crypto.py   # 加解密与 KDF 测试
│   ├── test_file_enc.py # 文件加解密测试
│   └── fixtures/        # 测试用样本文件
│       ├── sample.txt
│       └── sample.jpg
└── build/               # 打包配置
    ├── build.bat        # Windows 打包
    ├── build.sh         # Linux/macOS 打包
    └── aes256vault.spec # PyInstaller 规格文件
```

---

## 使用说明

### 文本加密

1. 打开 **「文本加密」** 标签页。
2. 在输入框中填入**明文**（加密时）或 **Base64 密文**（解密时）。
3. 输入密码；界面会实时显示密码强度。
4. 点击 **加密** 或 **解密**，结果会显示在下方输出框。
5. 可使用 **复制结果**、**清空** 方便后续操作。

### 文件加密

1. 打开 **「文件加密」** 标签页。
2. **加密**：选择待加密文件、输出目录与密码，点击 **加密文件**。生成 `.vault` 文件，内含原始文件名与大小。
3. **解密**：选择 `.vault` 文件、输出目录与密码，点击 **解密文件**。程序会恢复原始文件名；若目标目录已有同名文件，会自动命名为 `原名_1`、`原名_2` 等。

### 关于

在 **「关于」** 标签页可查看算法参数与安全提示。

---

## 测试

```bash
pip install pytest
pytest tests/ -v --tb=short
```

---

## 打包为可执行文件

```bash
pip install pyinstaller
cd build
pyinstaller aes256vault.spec
```

- **Windows**：可执行文件位于 `dist/AES256Vault.exe`
- **Linux / macOS**：可执行文件位于 `dist/AES256Vault`

---

## 安全概要

- **加密算法**：AES-256-GCM，96-bit nonce，128-bit 认证标签。
- **密钥派生**：Scrypt，N=2¹⁷、r=8、p=1；256-bit 随机盐，输出 256-bit 密钥。
- **文件格式**：魔数 `AES256V` + 版本号 + 盐 + nonce + 文件名长度与内容 + 原始大小 + 密文与标签。
- **错误处理**：密码错误或数据遭篡改时，统一提示「密码错误或数据已被篡改」，不区分具体原因以防信息泄露。

---

## 免责声明

本项目仅供学习与合规使用；请遵守当地法律法规，作者不对误用或数据丢失承担责任。
