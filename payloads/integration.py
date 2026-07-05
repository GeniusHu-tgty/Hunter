#!/usr/bin/env python3
"""
Hunter Payload 知识库集成模块
将 payload 知识库集成到 Hunter 的 fuzz/inject 工具中
"""

import os
import sys
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from payloads.loader import PayloadLoader


class PayloadIntegration:
    """Payload 知识库集成类"""

    def __init__(self):
        self.loader = PayloadLoader()

    def get_fuzz_payloads(self, vuln_type: str, context: Dict[str, Any] = None) -> List[str]:
        """获取用于 fuzz 的 payload 列表"""
        if context is None:
            context = {}

        try:
            payloads = self.loader.get_payloads(vuln_type)
            result = []
            self._extract_fuzz_payloads(payloads, context, result)
            return result
        except FileNotFoundError:
            return []

    def _extract_fuzz_payloads(self, data: Any, context: Dict[str, Any], result: List[str]):
        """递归提取 fuzz payload"""
        if isinstance(data, str):
            # 替换占位符
            payload = data
            for key, value in context.items():
                payload = payload.replace(f'{{{key}}}', value)
            if '{' not in payload:  # 只添加没有未替换占位符的 payload
                result.append(payload)
        elif isinstance(data, list):
            for item in data:
                self._extract_fuzz_payloads(item, context, result)
        elif isinstance(data, dict):
            for value in data.values():
                self._extract_fuzz_payloads(value, context, result)

    def get_inject_payloads(self, vuln_type: str, injection_point: str) -> List[Dict[str, Any]]:
        """获取用于注入测试的 payload 列表（带元数据）"""
        try:
            payloads = self.loader.get_payloads(vuln_type)
            result = []
            self._extract_inject_payloads(payloads, injection_point, result)
            return result
        except FileNotFoundError:
            return []

    def _extract_inject_payloads(self, data: Any, injection_point: str, result: List[Dict[str, Any]]):
        """递归提取注入 payload"""
        if isinstance(data, str):
            result.append({
                'payload': data,
                'injection_point': injection_point,
                'type': 'string'
            })
        elif isinstance(data, list):
            for item in data:
                self._extract_inject_payloads(item, injection_point, result)
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    result.append({
                        'payload': value,
                        'injection_point': injection_point,
                        'type': key
                    })
                else:
                    self._extract_inject_payloads(value, injection_point, result)

    def get_detection_payloads(self, vuln_type: str) -> List[str]:
        """获取用于检测漏洞是否存在的 payload"""
        try:
            payloads = self.loader.get_payloads(vuln_type)
            if 'detection' in payloads:
                result = []
                self._extract_fuzz_payloads(payloads['detection'], {}, result)
                return result
            return []
        except FileNotFoundError:
            return []

    def get_bypass_payloads(self, vuln_type: str, filter_type: str = None) -> List[str]:
        """获取用于绕过过滤的 payload"""
        try:
            payloads = self.loader.get_payloads(vuln_type)
            result = []

            if 'bypass' in payloads:
                bypass_data = payloads['bypass']
                if filter_type and filter_type in bypass_data:
                    self._extract_fuzz_payloads(bypass_data[filter_type], {}, result)
                else:
                    self._extract_fuzz_payloads(bypass_data, {}, result)

            if 'waf_bypass' in payloads:
                self._extract_fuzz_payloads(payloads['waf_bypass'], {}, result)

            return result
        except FileNotFoundError:
            return []

    def get_payloads_for_scanner(self, scanner_type: str) -> Dict[str, List[str]]:
        """获取特定扫描器的 payload 集合"""
        payload_map = {
            'sqli': ['sqli'],
            'xss': ['xss'],
            'ssti': ['ssti'],
            'ssrf': ['ssrf'],
            'lfi': ['lfi'],
            'rce': ['rce'],
            'xxe': ['xxe'],
            'jwt': ['jwt'],
            'upload': ['upload'],
            'deser': ['deser'],
            'info_leak': ['info_leak'],
            'web': ['sqli', 'xss', 'ssti', 'ssrf', 'lfi', 'rce', 'xxe'],
            'api': ['jwt', 'sqli', 'ssrf'],
            'full': list(self.loader.list_types())
        }

        types = payload_map.get(scanner_type, [scanner_type])
        result = {}

        for ptype in types:
            try:
                payloads = self.loader.get_payloads(ptype)
                result[ptype] = self._flatten_all_payloads(payloads)
            except FileNotFoundError:
                continue

        return result

    def _flatten_all_payloads(self, data: Any) -> List[str]:
        """扁平化所有 payload"""
        result = []
        self.loader._flatten_payloads(data, result)
        return result


class FuzzPayloadGenerator:
    """Fuzz Payload 生成器"""

    def __init__(self):
        self.integration = PayloadIntegration()

    def generate_sqli_fuzz(self, target_url: str, param: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """生成 SQL 注入 fuzz payload"""
        payloads = self.integration.get_fuzz_payloads('sqli')
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': method,
                'type': 'sqli'
            })

        return result

    def generate_xss_fuzz(self, target_url: str, param: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """生成 XSS fuzz payload"""
        payloads = self.integration.get_fuzz_payloads('xss')
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': method,
                'type': 'xss'
            })

        return result

    def generate_ssti_fuzz(self, target_url: str, param: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """生成 SSTI fuzz payload"""
        payloads = self.integration.get_fuzz_payloads('ssti')
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': method,
                'type': 'ssti'
            })

        return result

    def generate_ssrf_fuzz(self, target_url: str, param: str, callback_url: str = None) -> List[Dict[str, Any]]:
        """生成 SSRF fuzz payload"""
        context = {}
        if callback_url:
            context['your_server'] = callback_url
            context['dnslog'] = callback_url

        payloads = self.integration.get_fuzz_payloads('ssrf', context)
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': 'GET',
                'type': 'ssrf'
            })

        return result

    def generate_lfi_fuzz(self, target_url: str, param: str, method: str = 'GET') -> List[Dict[str, Any]]:
        """生成 LFI fuzz payload"""
        payloads = self.integration.get_fuzz_payloads('lfi')
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': method,
                'type': 'lfi'
            })

        return result

    def generate_rce_fuzz(self, target_url: str, param: str, callback_url: str = None) -> List[Dict[str, Any]]:
        """生成 RCE fuzz payload"""
        context = {}
        if callback_url:
            context['ip'] = callback_url.split(':')[0] if ':' in callback_url else callback_url
            context['port'] = callback_url.split(':')[1] if ':' in callback_url else '4444'
            context['dnslog'] = callback_url

        payloads = self.integration.get_fuzz_payloads('rce', context)
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': 'GET',
                'type': 'rce'
            })

        return result

    def generate_xxe_fuzz(self, target_url: str, param: str = None, callback_url: str = None) -> List[Dict[str, Any]]:
        """生成 XXE fuzz payload"""
        context = {}
        if callback_url:
            context['your-server'] = callback_url
            context['your-dnslog'] = callback_url

        payloads = self.integration.get_fuzz_payloads('xxe', context)
        result = []

        for payload in payloads:
            result.append({
                'url': target_url,
                'param': param,
                'payload': payload,
                'method': 'POST',
                'type': 'xxe'
            })

        return result


def test_integration():
    """测试集成功能"""
    integration = PayloadIntegration()
    generator = FuzzPayloadGenerator()

    print("=== 测试 Payload 知识库集成 ===\n")

    # 测试列出所有类型
    print("1. 可用的 Payload 类型:")
    for ptype in integration.loader.list_types():
        print(f"   - {ptype}")

    # 测试获取 SQL 注入 payload
    print("\n2. SQL 注入 payload 数量:")
    sqli_payloads = integration.get_fuzz_payloads('sqli')
    print(f"   总计: {len(sqli_payloads)} 个")

    # 测试获取 XSS payload
    print("\n3. XSS payload 数量:")
    xss_payloads = integration.get_fuzz_payloads('xss')
    print(f"   总计: {len(xss_payloads)} 个")

    # 测试获取 SSRF payload
    print("\n4. SSRF payload 数量:")
    ssrf_payloads = integration.get_fuzz_payloads('ssrf')
    print(f"   总计: {len(ssrf_payloads)} 个")

    # 测试生成 fuzz payload
    print("\n5. 生成 SQL 注入 fuzz payload:")
    fuzz_payloads = generator.generate_sqli_fuzz('http://target.com/login', 'username')
    print(f"   生成了 {len(fuzz_payloads)} 个 payload")
    if fuzz_payloads:
        print(f"   示例: {fuzz_payloads[0]['payload'][:50]}...")

    # 测试获取检测 payload
    print("\n6. SQL 注入检测 payload:")
    detection_payloads = integration.get_detection_payloads('sqli')
    print(f"   总计: {len(detection_payloads)} 个")
    for p in detection_payloads[:3]:
        print(f"   - {p}")

    # 测试获取绕过 payload
    print("\n7. SQL 注入 WAF 绕过 payload:")
    bypass_payloads = integration.get_bypass_payloads('sqli', 'space_bypass')
    print(f"   总计: {len(bypass_payloads)} 个")
    for p in bypass_payloads[:3]:
        print(f"   - {p}")

    print("\n=== 测试完成 ===")


if __name__ == '__main__':
    test_integration()
