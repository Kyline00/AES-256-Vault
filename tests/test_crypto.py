# -*- coding: utf-8 -*-
"""加密引擎与文本加解密单元测试"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from base64 import b64decode, b64encode
from aes256_vault import CryptoEngine


class TestTextEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        """基本加解密往返测试"""
        original = "Hello 世界 🔐"
        password = "TestPass123!"
        cipher = CryptoEngine.encrypt_text(original, password)
        result = CryptoEngine.decrypt_text(cipher, password)
        assert result == original

    def test_different_ciphertexts_same_input(self):
        """相同输入每次产生不同密文（随机盐+随机nonce）"""
        pw = "pass"
        txt = "hello"
        c1 = CryptoEngine.encrypt_text(txt, pw)
        c2 = CryptoEngine.encrypt_text(txt, pw)
        assert c1 != c2

    def test_wrong_password_raises(self):
        """错误密码应抛出 ValueError"""
        cipher = CryptoEngine.encrypt_text("secret", "correctpass")
        with pytest.raises(ValueError):
            CryptoEngine.decrypt_text(cipher, "wrongpass")

    def test_tampered_ciphertext_raises(self):
        """篡改密文应被认证标签检测到"""
        cipher = CryptoEngine.encrypt_text("secret", "pass")
        raw = bytearray(b64decode(cipher))
        raw[50] ^= 0xFF
        with pytest.raises(ValueError):
            CryptoEngine.decrypt_text(b64encode(raw).decode(), "pass")

    def test_unicode_content(self):
        """Unicode 内容（中文、emoji、特殊符号）"""
        content = "你好世界！😀 αβγδ ℃ €$¥"
        cipher = CryptoEngine.encrypt_text(content, "pass123")
        assert CryptoEngine.decrypt_text(cipher, "pass123") == content

    def test_long_content(self):
        """大文本（1MB）"""
        content = "A" * 1_000_000
        cipher = CryptoEngine.encrypt_text(content, "pass")
        assert CryptoEngine.decrypt_text(cipher, "pass") == content

    def test_empty_string(self):
        """空字符串加密"""
        cipher = CryptoEngine.encrypt_text("", "pass")
        assert CryptoEngine.decrypt_text(cipher, "pass") == ""


class TestPasswordStrength:
    @pytest.mark.parametrize(
        "pw,min_score,label_fragment",
        [
            ("abc", 0, "弱"),
            ("password", 20, ""),
            ("Password1", 57, ""),
            ("MyStr0ng@Pass!2024", 87, "极强"),
        ],
    )
    def test_strength_scores(self, pw, min_score, label_fragment):
        score, label = CryptoEngine.password_strength(pw)
        assert score >= min_score
        if label_fragment:
            assert label_fragment in label


class TestFileEncryption:
    def test_file_roundtrip(self, tmp_path):
        """文件加解密往返：内容完全一致"""
        src = tmp_path / "test.txt"
        src.write_bytes(b"Binary content \x00\x01\x02\xff")
        dst = tmp_path / "test.vault"
        CryptoEngine.encrypt_file(str(src), str(dst), "filepass")
        CryptoEngine.decrypt_file(str(dst), str(tmp_path), "filepass")
        recovered = tmp_path / "test.txt"
        assert recovered.read_bytes() == src.read_bytes()

    def test_wrong_password_file(self, tmp_path):
        """文件解密密码错误"""
        src = tmp_path / "f.bin"
        src.write_bytes(b"data")
        dst = tmp_path / "f.vault"
        CryptoEngine.encrypt_file(str(src), str(dst), "correct")
        with pytest.raises(ValueError):
            CryptoEngine.decrypt_file(str(dst), str(tmp_path), "wrong")

    def test_invalid_vault_file(self, tmp_path):
        """非 vault 文件应被拒绝"""
        f = tmp_path / "fake.vault"
        f.write_bytes(b"not a vault file")
        with pytest.raises(ValueError, match="不是有效的"):
            CryptoEngine.decrypt_file(str(f), str(tmp_path), "pass")
