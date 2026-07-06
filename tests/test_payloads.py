"""
Hunter v7 Payload 知识库测试
"""

import pytest
import os
import yaml


PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), '..', 'payloads')


class TestPayloadFiles:
    """测试 Payload 文件存在且格式正确"""

    def test_payloads_dir_exists(self):
        assert os.path.isdir(PAYLOADS_DIR)

    def test_sqli_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'sqli', 'payloads.yaml')
        assert os.path.exists(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_xss_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'xss', 'payloads.yaml')
        assert os.path.exists(path)
        with open(path) as f:
            data = yaml.safe_load(f)
        assert data is not None

    def test_ssrf_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'ssrf', 'payloads.yaml')
        assert os.path.exists(path)

    def test_ssti_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'ssti', 'payloads.yaml')
        assert os.path.exists(path)

    def test_lfi_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'lfi', 'payloads.yaml')
        assert os.path.exists(path)

    def test_rce_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'rce', 'payloads.yaml')
        assert os.path.exists(path)

    def test_jwt_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'jwt', 'payloads.yaml')
        assert os.path.exists(path)

    def test_upload_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'upload', 'payloads.yaml')
        assert os.path.exists(path)

    def test_xxe_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'xxe', 'payloads.yaml')
        assert os.path.exists(path)

    def test_deser_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'deser', 'payloads.yaml')
        assert os.path.exists(path)

    def test_info_leak_payloads(self):
        path = os.path.join(PAYLOADS_DIR, 'info_leak', 'payloads.yaml')
        assert os.path.exists(path)


class TestPayloadFormat:
    """测试 Payload 格式"""

    def _count_payloads_recursive(self, data):
        """递归计算 payload 数量"""
        count = 0
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ('metadata', 'description', 'category', 'version', 'type', 'range', 'note'):
                    continue
                if isinstance(value, str) and len(value) > 2:
                    count += 1
                elif isinstance(value, list):
                    for item in value:
                        count += self._count_payloads_recursive(item)
                elif isinstance(value, dict):
                    count += self._count_payloads_recursive(value)
        elif isinstance(data, str) and len(data) > 2:
            count += 1
        return count

    def test_payload_count(self):
        """验证总 payload 数量 >= 680"""
        total = 0
        for vuln_type in os.listdir(PAYLOADS_DIR):
            path = os.path.join(PAYLOADS_DIR, vuln_type, 'payloads.yaml')
            if os.path.exists(path):
                with open(path) as f:
                    data = yaml.safe_load(f)
                total += self._count_payloads_recursive(data)
        assert total >= 680, f"Expected 680+ payloads, got {total}"
