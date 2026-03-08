# -*- coding: utf-8 -*-
"""
AES-256 Vault — 安全加密软件
算法: AES-256-GCM + Scrypt KDF | 零知识 · 本地加密 · 防篡改
"""

import os
import sys
import struct
import hashlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import binascii
from base64 import b64encode, b64decode
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ---------------------------------------------------------------------------
# 安全参数常量（不要随意修改！）
# ---------------------------------------------------------------------------
SCRYPT_N       = 2 ** 17   # 131,072 — CPU/内存工作因子
SCRYPT_N_FAST  = 2 ** 14   # 快速模式（UI 预览不阻塞）
SCRYPT_R       = 8
SCRYPT_P       = 1
SALT_BYTES     = 32        # 256-bit 随机盐
NONCE_BYTES    = 12        # 96-bit nonce（GCM 标准推荐）
KEY_BYTES      = 32        # 256-bit AES 密钥
TAG_BYTES      = 16        # 128-bit GCM 认证标签
FILE_MAGIC     = b"AES256V"
FILE_VERSION   = 1


class CryptoEngine:
    """加密引擎：Scrypt KDF + AES-256-GCM"""

    @staticmethod
    def derive_key(password: str, salt: bytes, fast: bool = False) -> bytes:
        n = SCRYPT_N_FAST if fast else SCRYPT_N
        # OpenSSL 默认 maxmem 约 32 MiB，需显式传入以满足 N=2^17 时的 128*N*r
        maxmem = 128 * n * SCRYPT_R + (1 << 20)  # 128*N*r + 1MB 余量
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n, r=SCRYPT_R, p=SCRYPT_P,
            dklen=KEY_BYTES,
            maxmem=maxmem,
        )

    @staticmethod
    def encrypt_text(plaintext: str, password: str) -> str:
        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        key = CryptoEngine.derive_key(password, salt)
        ct_tag = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return b64encode(salt + nonce + ct_tag).decode("ascii")

    @staticmethod
    def decrypt_text(cipherblob: str, password: str) -> str:
        try:
            # 规范化 Base64：去掉空白、补足填充，避免「incorrect padding」
            s = "".join(cipherblob.split()).strip()
            pad = (4 - len(s) % 4) % 4
            s = s + "=" * pad
            raw = b64decode(s)
            if len(raw) < SALT_BYTES + NONCE_BYTES + TAG_BYTES:
                raise ValueError("密文格式错误或已损坏，请检查是否完整复制")
            salt = raw[:SALT_BYTES]
            nonce = raw[SALT_BYTES : SALT_BYTES + NONCE_BYTES]
            ct_tag = raw[SALT_BYTES + NONCE_BYTES :]
            key = CryptoEngine.derive_key(password, salt)
            return AESGCM(key).decrypt(nonce, ct_tag, None).decode("utf-8")
        except (binascii.Error, ValueError) as e:
            if "padding" in str(e).lower() or "incorrect" in str(e).lower():
                raise ValueError("密文格式错误或已损坏（可能复制不完整），请检查 Base64 密文是否完整")
            raise ValueError("密文格式错误或已损坏，请检查是否完整复制")
        except InvalidTag:
            raise ValueError("密码错误或数据已被篡改")

    @staticmethod
    def password_strength(password: str) -> tuple:
        """评分 0–100，返回 (score, label)。"""
        score = 0
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 15
        if len(password) >= 16:
            score += 15
        if any(c.isupper() for c in password):
            score += 12
        if any(c.islower() for c in password):
            score += 12
        if any(c.isdigit() for c in password):
            score += 13
        if any(not c.isalnum() for c in password):
            score += 13
        score = min(100, score)
        if score <= 24:
            label = "极弱 Very Weak"
        elif score <= 44:
            label = "弱 Weak"
        elif score <= 64:
            label = "中等 Fair"
        elif score <= 79:
            label = "强 Strong"
        else:
            label = "极强 Very Strong"
        return score, label

    @staticmethod
    def encrypt_file(src_path: str, dst_path: str, password: str, progress_cb=None) -> dict:
        src = Path(src_path)
        file_size = src.stat().st_size
        salt = os.urandom(SALT_BYTES)
        nonce = os.urandom(NONCE_BYTES)
        key = CryptoEngine.derive_key(password, salt)
        fname_bytes = src.name.encode("utf-8")

        with open(src_path, "rb") as f:
            plaindata = f.read()

        if progress_cb:
            progress_cb(50)
        ct_tag = AESGCM(key).encrypt(nonce, plaindata, None)
        if progress_cb:
            progress_cb(90)

        with open(dst_path, "wb") as f:
            f.write(FILE_MAGIC)
            f.write(bytes([FILE_VERSION]))
            f.write(salt)
            f.write(nonce)
            f.write(struct.pack(">H", len(fname_bytes)))
            f.write(fname_bytes)
            f.write(struct.pack(">Q", file_size))
            f.write(ct_tag)

        if progress_cb:
            progress_cb(100)
        return {
            "original_name": src.name,
            "original_size": file_size,
            "encrypted_size": Path(dst_path).stat().st_size,
            "algorithm": "AES-256-GCM",
            "kdf": "Scrypt(N=2^17,r=8,p=1)",
        }

    @staticmethod
    def decrypt_file(src_path: str, dst_dir: str, password: str, progress_cb=None) -> dict:
        with open(src_path, "rb") as f:
            if f.read(7) != FILE_MAGIC:
                raise ValueError("不是有效的 AES-256 Vault 文件")
            f.read(1)  # version
            salt = f.read(SALT_BYTES)
            nonce = f.read(NONCE_BYTES)
            fname_len = struct.unpack(">H", f.read(2))[0]
            orig_name = f.read(fname_len).decode("utf-8")
            orig_size = struct.unpack(">Q", f.read(8))[0]
            ct_tag = f.read()

        if progress_cb:
            progress_cb(40)
        key = CryptoEngine.derive_key(password, salt)

        try:
            plaindata = AESGCM(key).decrypt(nonce, ct_tag, None)
        except InvalidTag:
            raise ValueError("密码错误或文件已被篡改")

        if progress_cb:
            progress_cb(80)

        out_path = Path(dst_dir) / orig_name
        counter = 1
        while out_path.exists():
            stem, suffix = Path(orig_name).stem, Path(orig_name).suffix
            out_path = Path(dst_dir) / f"{stem}_{counter}{suffix}"
            counter += 1

        with open(out_path, "wb") as f:
            f.write(plaindata)

        if progress_cb:
            progress_cb(100)
        return {
            "original_name": orig_name,
            "original_size": orig_size,
            "saved_to": str(out_path),
        }


# ---------------------------------------------------------------------------
# GUI 配色与字体（GitHub Dark 风格）
# ---------------------------------------------------------------------------
BG      = "#0d1117"
BG2     = "#161b22"
BG3     = "#21262d"
BORDER  = "#30363d"
ACCENT  = "#58a6ff"
ACCENT2 = "#3fb950"
DANGER  = "#f85149"
WARN    = "#d29922"
TEXT    = "#e6edf3"
TEXT2   = "#8b949e"

FONT_TITLE = ("Segoe UI", 14, "bold")
FONT_BODY  = ("Segoe UI", 10)
FONT_MONO  = ("Consolas", 10)


class AESVaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AES-256 Vault — 安全加密")
        self.geometry("820x620")
        self.minsize(720, 520)
        self.configure(bg=BG)

        self._style_ttk()
        self._build_ui()

    def _style_ttk(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=BG3)
        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab", background=BG2, foreground=TEXT2, padding=(12, 6))
        style.map("TNotebook.Tab", background=[("selected", BG3)], foreground=[("selected", TEXT)])
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("TLabelframe", background=BG2, foreground=TEXT)
        style.configure("TLabelframe.Label", background=BG2, foreground=TEXT)
        style.configure("TButton", background=BG3, foreground=TEXT, padding=(10, 6))
        style.map("TButton", background=[("active", BORDER)], foreground=[("active", ACCENT)])
        style.configure("TProgressbar", background=ACCENT, troughcolor=BG3, thickness=8)
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.configure("TEntry", fieldbackground=BG3, foreground=TEXT)

    def _build_ui(self):
        # Header
        header = tk.Frame(self, bg=BG2, height=52)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        tk.Label(
            header, text="AES-256 Vault", font=FONT_TITLE, fg=TEXT, bg=BG2
        ).pack(side=tk.LEFT, padx=16, pady=10)
        tk.Label(
            header, text="AES-256-GCM + Scrypt · 零网络 · 本地加密",
            font=("Segoe UI", 9), fg=TEXT2, bg=BG2,
        ).pack(side=tk.LEFT, padx=0, pady=10)

        # 分隔线
        sep = tk.Frame(self, height=1, bg=BORDER)
        sep.pack(fill=tk.X)

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        self.tab_text = ttk.Frame(self.notebook, padding=8)
        self.tab_file = ttk.Frame(self.notebook, padding=8)
        self.tab_info = ttk.Frame(self.notebook, padding=8)

        self.notebook.add(self.tab_text, text="  文本加密  ")
        self.notebook.add(self.tab_file, text="  文件加密  ")
        self.notebook.add(self.tab_info, text="  关于  ")

        self._build_text_tab()
        self._build_file_tab()
        self._build_info_tab()

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        status_bar = tk.Frame(self, bg=BG2, height=24)
        status_bar.pack(fill=tk.X)
        status_bar.pack_propagate(False)
        tk.Label(
            status_bar, textvariable=self.status_var, font=("Segoe UI", 9),
            fg=TEXT2, bg=BG2,
        ).pack(side=tk.LEFT, padx=12, pady=2)

    def _make_btn(self, parent, text, cmd, **kw):
        btn = tk.Button(
            parent, text=text, command=cmd,
            bg=BG3, fg=TEXT, activebackground=BORDER, activeforeground=ACCENT,
            relief=tk.FLAT, padx=12, pady=6, font=FONT_BODY,
            cursor="hand2", **kw
        )
        btn.bind("<Enter>", lambda e: btn.configure(bg=BORDER))
        btn.bind("<Leave>", lambda e: btn.configure(bg=BG3))
        return btn

    def _build_text_tab(self):
        # 输入区
        card_in = tk.Frame(self.tab_text, bg=BG2, padx=12, pady=10)
        card_in.pack(fill=tk.X, pady=(0, 8))
        tk.Label(card_in, text="明文 / 密文", font=FONT_BODY, fg=TEXT2, bg=BG2).pack(anchor=tk.W)
        self.text_input = tk.Text(card_in, height=6, wrap=tk.WORD, bg=BG3, fg=TEXT, insertbackground=TEXT,
                                  relief=tk.FLAT, padx=8, pady=8, font=FONT_MONO)
        self.text_input.pack(fill=tk.X, pady=4)

        # 密码区
        pwd_frame = tk.Frame(self.tab_text, bg=BG)
        pwd_frame.pack(fill=tk.X, pady=4)
        tk.Label(pwd_frame, text="密码", font=FONT_BODY, fg=TEXT2, bg=BG, width=6, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 8))
        self.text_pwd_var = tk.StringVar()
        self.text_pwd_entry = tk.Entry(
            pwd_frame, textvariable=self.text_pwd_var, show="●",
            bg=BG3, fg=TEXT, insertbackground=TEXT, relief=tk.FLAT, width=28, font=FONT_BODY
        )
        self.text_pwd_entry.pack(side=tk.LEFT, padx=4)
        self.text_show_pwd = tk.BooleanVar(value=False)

        def toggle_show():
            self.text_pwd_entry.configure(show="" if self.text_show_pwd.get() else "●")
        tk.Checkbutton(
            pwd_frame, text="显示", variable=self.text_show_pwd, command=toggle_show,
            bg=BG, fg=TEXT2, selectcolor=BG3, activebackground=BG, activeforeground=TEXT
        ).pack(side=tk.LEFT)

        strength_frame = tk.Frame(self.tab_text, bg=BG)
        strength_frame.pack(fill=tk.X, pady=2)
        self.text_strength_bar = ttk.Progressbar(strength_frame, length=200, mode="determinate")
        self.text_strength_bar.pack(side=tk.LEFT, padx=(0, 8))
        self.text_strength_label = tk.Label(strength_frame, text="", font=("Segoe UI", 9), fg=TEXT2, bg=BG)
        self.text_strength_label.pack(side=tk.LEFT)

        self.text_pwd_var.trace_add("write", lambda *a: self._update_text_strength())
        self._update_text_strength()

        # 按钮行
        btn_frame = tk.Frame(self.tab_text, bg=BG)
        btn_frame.pack(fill=tk.X, pady=8)
        self._make_btn(btn_frame, "加密", self._text_encrypt).pack(side=tk.LEFT, padx=(0, 8))
        self._make_btn(btn_frame, "解密", self._text_decrypt).pack(side=tk.LEFT, padx=(0, 8))
        self._make_btn(btn_frame, "复制结果", self._text_copy).pack(side=tk.LEFT, padx=(0, 8))
        self._make_btn(btn_frame, "清空", self._text_clear).pack(side=tk.LEFT)

        # 输出区
        card_out = tk.Frame(self.tab_text, bg=BG2, padx=12, pady=10)
        card_out.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        tk.Label(card_out, text="输出", font=FONT_BODY, fg=TEXT2, bg=BG2).pack(anchor=tk.W)
        self.text_output = tk.Text(card_out, height=8, wrap=tk.WORD, bg=BG3, fg=TEXT, state=tk.DISABLED,
                                   relief=tk.FLAT, padx=8, pady=8, font=FONT_MONO)
        self.text_output.pack(fill=tk.BOTH, expand=True, pady=4)

    def _update_text_strength(self):
        pw = self.text_pwd_var.get()
        score, label = CryptoEngine.password_strength(pw)
        self.text_strength_bar["value"] = score
        self.text_strength_label.configure(text=label)
        if score <= 44:
            self.text_strength_label.configure(fg=DANGER)
        elif score <= 64:
            self.text_strength_label.configure(fg=WARN)
        else:
            self.text_strength_label.configure(fg=ACCENT2)

    def _text_encrypt(self):
        plain = self.text_input.get("1.0", tk.END).strip()
        pw = self.text_pwd_var.get()
        if not pw:
            messagebox.showwarning("提示", "请输入密码", parent=self)
            return
        try:
            cipher = CryptoEngine.encrypt_text(plain, pw)
            self.text_output.configure(state=tk.NORMAL)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", cipher)
            self.text_output.configure(state=tk.DISABLED)
            self.status_var.set("文本已加密")
        except Exception as e:
            messagebox.showerror("错误", str(e), parent=self)

    def _text_decrypt(self):
        cipher = self.text_input.get("1.0", tk.END).strip()
        pw = self.text_pwd_var.get()
        if not cipher or not pw:
            messagebox.showwarning("提示", "请输入密文和密码", parent=self)
            return
        try:
            plain = CryptoEngine.decrypt_text(cipher, pw)
            self.text_output.configure(state=tk.NORMAL)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", plain)
            self.text_output.configure(state=tk.DISABLED)
            self.status_var.set("文本已解密")
        except ValueError as e:
            messagebox.showerror("解密失败", str(e), parent=self)
        except Exception as e:
            messagebox.showerror("错误", str(e), parent=self)

    def _text_copy(self):
        out = self.text_output.get("1.0", tk.END).strip()
        if out:
            self.clipboard_clear()
            self.clipboard_append(out)
            self.status_var.set("已复制到剪贴板")

    def _text_clear(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.configure(state=tk.NORMAL)
        self.text_output.delete("1.0", tk.END)
        self.text_output.configure(state=tk.DISABLED)
        self.status_var.set("已清空")

    def _build_file_tab(self):
        # 文件选择
        file_frame = tk.Frame(self.tab_file, bg=BG2, padx=12, pady=10)
        file_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(file_frame, text="文件", font=FONT_BODY, fg=TEXT2, bg=BG2).pack(anchor=tk.W)
        self.file_path_var = tk.StringVar()
        self.file_path_label = tk.Label(
            file_frame, textvariable=self.file_path_var, font=FONT_MONO, fg=TEXT2, bg=BG2, anchor=tk.W
        )
        self.file_path_label.pack(fill=tk.X, pady=4)
        tk.Button(
            file_frame, text="选择文件...", command=self._pick_file,
            bg=BG3, fg=TEXT, relief=tk.FLAT, padx=10, pady=4, cursor="hand2"
        ).pack(anchor=tk.W)

        # 输出目录
        out_frame = tk.Frame(self.tab_file, bg=BG2, padx=12, pady=10)
        out_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(out_frame, text="输出目录", font=FONT_BODY, fg=TEXT2, bg=BG2).pack(anchor=tk.W)
        self.out_dir_var = tk.StringVar()
        self.out_dir_label = tk.Label(
            out_frame, textvariable=self.out_dir_var, font=FONT_MONO, fg=TEXT2, bg=BG2, anchor=tk.W
        )
        self.out_dir_label.pack(fill=tk.X, pady=4)
        tk.Button(
            out_frame, text="选择目录...", command=self._pick_outdir,
            bg=BG3, fg=TEXT, relief=tk.FLAT, padx=10, pady=4, cursor="hand2"
        ).pack(anchor=tk.W)

        # 密码
        fpwd_frame = tk.Frame(self.tab_file, bg=BG)
        fpwd_frame.pack(fill=tk.X, pady=4)
        tk.Label(fpwd_frame, text="密码", font=FONT_BODY, fg=TEXT2, bg=BG, width=6, anchor=tk.W).pack(side=tk.LEFT, padx=(0, 8))
        self.file_pwd_var = tk.StringVar()
        self.file_pwd_entry = tk.Entry(
            fpwd_frame, textvariable=self.file_pwd_var, show="●",
            bg=BG3, fg=TEXT, insertbackground=TEXT, relief=tk.FLAT, width=28, font=FONT_BODY
        )
        self.file_pwd_entry.pack(side=tk.LEFT, padx=4)

        fstr_frame = tk.Frame(self.tab_file, bg=BG)
        fstr_frame.pack(fill=tk.X, pady=2)
        self.file_strength_bar = ttk.Progressbar(fstr_frame, length=200, mode="determinate")
        self.file_strength_bar.pack(side=tk.LEFT, padx=(0, 8))
        self.file_strength_label = tk.Label(fstr_frame, text="", font=("Segoe UI", 9), fg=TEXT2, bg=BG)
        self.file_strength_label.pack(side=tk.LEFT)

        self.file_pwd_var.trace_add("write", lambda *a: self._update_file_strength())
        self._update_file_strength()

        # 进度条
        prog_frame = tk.Frame(self.tab_file, bg=BG)
        prog_frame.pack(fill=tk.X, pady=8)
        self.file_progress = ttk.Progressbar(prog_frame, length=300, mode="determinate")
        self.file_progress.pack(fill=tk.X)

        # 按钮
        fbtn_frame = tk.Frame(self.tab_file, bg=BG)
        fbtn_frame.pack(fill=tk.X, pady=8)
        self._make_btn(fbtn_frame, "加密文件", self._file_encrypt).pack(side=tk.LEFT, padx=(0, 8))
        self._make_btn(fbtn_frame, "解密文件", self._file_decrypt).pack(side=tk.LEFT)

        # 结果
        self.file_result_var = tk.StringVar(value="")
        tk.Label(self.tab_file, textvariable=self.file_result_var, font=FONT_BODY, fg=ACCENT2, bg=BG).pack(anchor=tk.W, pady=4)

    def _update_file_strength(self):
        pw = self.file_pwd_var.get()
        score, label = CryptoEngine.password_strength(pw)
        self.file_strength_bar["value"] = score
        self.file_strength_label.configure(text=label)
        if score <= 44:
            self.file_strength_label.configure(fg=DANGER)
        elif score <= 64:
            self.file_strength_label.configure(fg=WARN)
        else:
            self.file_strength_label.configure(fg=ACCENT2)

    def _pick_file(self):
        path = filedialog.askopenfilename(parent=self, title="选择文件")
        if path:
            self.file_path_var.set(path)
            self.status_var.set("已选择: " + Path(path).name)

    def _pick_outdir(self):
        path = filedialog.askdirectory(parent=self, title="选择输出目录")
        if path:
            self.out_dir_var.set(path)
            self.status_var.set("输出目录: " + path)

    def _set_progress(self, v):
        self.after(0, lambda: self.file_progress.configure(value=v))

    def _file_encrypt(self):
        src = self.file_path_var.get().strip()
        out_dir = self.out_dir_var.get().strip() or str(Path(src).parent)
        pw = self.file_pwd_var.get()
        if not src or not Path(src).is_file():
            messagebox.showwarning("提示", "请先选择要加密的文件", parent=self)
            return
        if not pw:
            messagebox.showwarning("提示", "请输入密码", parent=self)
            return

        self.file_progress["value"] = 0
        self.file_result_var.set("加密中...")
        dst = str(Path(out_dir) / (Path(src).name + ".vault"))

        def run():
            try:
                meta = CryptoEngine.encrypt_file(
                    src, dst, pw, progress_cb=lambda v: self._set_progress(v)
                )
                msg = f"已加密: {meta['original_name']} → {Path(dst).name}"
                self.after(0, lambda: self.file_result_var.set(msg))
                self.after(0, lambda: self.status_var.set(msg))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", str(e), parent=self))
                self.after(0, lambda: self.file_result_var.set(""))
            self.after(0, lambda: self._set_progress(0))

        threading.Thread(target=run, daemon=True).start()

    def _file_decrypt(self):
        src = self.file_path_var.get().strip()
        out_dir = self.out_dir_var.get().strip() or str(Path(src).parent)
        pw = self.file_pwd_var.get()
        if not src or not Path(src).is_file():
            messagebox.showwarning("提示", "请先选择 .vault 文件", parent=self)
            return
        if not pw:
            messagebox.showwarning("提示", "请输入密码", parent=self)
            return

        self.file_progress["value"] = 0
        self.file_result_var.set("解密中...")

        def run():
            try:
                meta = CryptoEngine.decrypt_file(
                    src, out_dir, pw, progress_cb=lambda v: self._set_progress(v)
                )
                msg = f"已解密: {meta['original_name']} → {meta['saved_to']}"
                self.after(0, lambda: self.file_result_var.set(msg))
                self.after(0, lambda: self.status_var.set(msg))
            except ValueError as e:
                self.after(0, lambda: messagebox.showerror("解密失败", str(e), parent=self))
                self.after(0, lambda: self.file_result_var.set(""))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("错误", str(e), parent=self))
                self.after(0, lambda: self.file_result_var.set(""))
            self.after(0, lambda: self._set_progress(0))

        threading.Thread(target=run, daemon=True).start()

    def _build_info_tab(self):
        sections = [
            ("算法参数", [
                ("加密算法", "AES-256-GCM (AEAD)"),
                ("密钥派生", "Scrypt N=2^17, r=8, p=1"),
                ("密钥长度", "256 bit"),
                ("认证标签", "128 bit (GCM)"),
                ("盐 / Nonce", "256-bit / 96-bit 随机"),
            ]),
            ("文件格式", [
                ("扩展名", ".vault"),
                ("魔数", "AES256V (7 字节)"),
                ("自描述", "含原始文件名、大小"),
            ]),
            ("安全提示", [
                ("零网络", "所有运算均在本地完成"),
                ("防篡改", "任何字节修改将导致解密失败"),
                ("密码", "请使用强密码并妥善保管"),
            ]),
        ]
        for title, rows in sections:
            card = tk.Frame(self.tab_info, bg=BG2, padx=12, pady=10)
            card.pack(fill=tk.X, pady=4)
            tk.Label(card, text=title, font=FONT_BODY, fg=ACCENT, bg=BG2).pack(anchor=tk.W)
            tk.Frame(card, height=1, bg=BORDER).pack(fill=tk.X, pady=4)
            for k, v in rows:
                row = tk.Frame(card, bg=BG2)
                row.pack(fill=tk.X, pady=2)
                tk.Label(row, text=k + ":", font=FONT_BODY, fg=TEXT2, bg=BG2, width=12, anchor=tk.W).pack(side=tk.LEFT)
                tk.Label(row, text=v, font=FONT_MONO, fg=TEXT, bg=BG2, anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)


def main():
    app = AESVaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
