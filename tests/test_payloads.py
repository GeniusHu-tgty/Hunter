"""
Hunter v7 Payload 知识库测试
"""

import pytest
import os
import yaml


PAYLOADS_DIR = os.path.join(os.path.dirname(__file__), '..', 'payloads')
CORE_PAYLOAD_TYPES = {'deser', 'info_leak', 'jwt', 'lfi', 'sqli', 'ssti', 'xss', 'xxe'}


def _payload_yaml_path(payload_type):
    return os.path.join(PAYLOADS_DIR, payload_type, 'payloads.yaml')


def _load_payload_yaml(payload_type):
    with open(_payload_yaml_path(payload_type), encoding='utf-8') as f:
        return yaml.safe_load(f)


def _actual_payload_types():
    return {
        item
        for item in os.listdir(PAYLOADS_DIR)
        if os.path.exists(_payload_yaml_path(item))
    }


class TestPayloadFiles:
    """测试 Payload 文件存在且格式正确"""

    def test_payloads_dir_exists(self):
        assert os.path.isdir(PAYLOADS_DIR)

    def test_core_payload_inventory_matches_repo(self):
        """核心 payload 类型以仓库实际 YAML 为准，避免 stale 目录断言。"""
        assert CORE_PAYLOAD_TYPES.issubset(_actual_payload_types())

    @pytest.mark.parametrize('payload_type', sorted(CORE_PAYLOAD_TYPES))
    def test_core_payload_yaml_loads_as_utf8(self, payload_type):
        path = _payload_yaml_path(payload_type)
        assert os.path.exists(path)
        data = _load_payload_yaml(payload_type)
        assert data is not None


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
            path = _payload_yaml_path(vuln_type)
            if os.path.exists(path):
                with open(path, encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                total += self._count_payloads_recursive(data)
        assert total >= 680, f"Expected 680+ payloads, got {total}"
