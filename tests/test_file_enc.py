# -*- coding: utf-8 -*-
"""文件加密集成测试（使用 fixtures）"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from aes256_vault import CryptoEngine

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


class TestFileEncryptionFixtures:
    def test_encrypt_decrypt_sample_txt(self, tmp_path):
        """使用 fixtures/sample.txt 加解密"""
        sample = FIXTURES_DIR / "sample.txt"
        if not sample.exists():
            pytest.skip("fixtures/sample.txt 不存在")
        dst = tmp_path / "sample.vault"
        CryptoEngine.encrypt_file(str(sample), str(dst), "fixture_pass")
        CryptoEngine.decrypt_file(str(dst), str(tmp_path), "fixture_pass")
        recovered = tmp_path / "sample.txt"
        assert recovered.read_bytes() == sample.read_bytes()

    def test_encrypt_decrypt_sample_binary(self, tmp_path):
        """使用 fixtures/sample.jpg 加解密（二进制）"""
        sample = FIXTURES_DIR / "sample.jpg"
        if not sample.exists():
            pytest.skip("fixtures/sample.jpg 不存在")
        dst = tmp_path / "sample.vault"
        CryptoEngine.encrypt_file(str(sample), str(dst), "fixture_pass")
        CryptoEngine.decrypt_file(str(dst), str(tmp_path), "fixture_pass")
        recovered = tmp_path / "sample.jpg"
        assert recovered.read_bytes() == sample.read_bytes()
