#!/usr/bin/env python3
"""
Hunter Payload 知识库加载器
用于加载和查询 YAML 格式的 Payload 文件
"""

import os
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional


class PayloadLoader:
    """Payload 加载器类"""

    def __init__(self, payload_dir: str = None):
        """初始化加载器"""
        if payload_dir is None:
            payload_dir = os.path.dirname(os.path.abspath(__file__))
        self.payload_dir = Path(payload_dir)
        self._cache = {}

    def list_types(self) -> List[str]:
        """列出所有 payload 类型"""
        types = []
        for item in self.payload_dir.iterdir():
            if item.is_dir() and (item / 'payloads.yaml').exists():
                types.append(item.name)
        return sorted(types)

    def get_payloads(self, payload_type: str) -> Dict[str, Any]:
        """获取指定类型的所有 payload"""
        if payload_type in self._cache:
            return self._cache[payload_type]

        payload_file = self.payload_dir / payload_type / 'payloads.yaml'
        if not payload_file.exists():
            raise FileNotFoundError(f"Payload file not found: {payload_file}")

        with open(payload_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        self._cache[payload_type] = data
        return data

    def get_section(self, payload_type: str, section: str) -> Dict[str, Any]:
        """获取指定类型和章节的 payload"""
        payloads = self.get_payloads(payload_type)
        if section not in payloads:
            raise KeyError(f"Section '{section}' not found in {payload_type}")
        return payloads[section]

    def get_all_payloads_flat(self, payload_type: str) -> List[str]:
        """获取指定类型的所有 payload（扁平化列表）"""
        payloads = self.get_payloads(payload_type)
        result = []
        self._flatten_payloads(payloads, result)
        return result

    def _flatten_payloads(self, data: Any, result: List[str]):
        """递归扁平化 payload"""
        if isinstance(data, str):
            result.append(data)
        elif isinstance(data, list):
            for item in data:
                self._flatten_payloads(item, result)
        elif isinstance(data, dict):
            for value in data.values():
                self._flatten_payloads(value, result)

    def search(self, keyword: str) -> List[Dict[str, Any]]:
        """搜索包含关键字的 payload"""
        results = []
        for payload_type in self.list_types():
            payloads = self.get_payloads(payload_type)
            self._search_in_data(payloads, keyword, payload_type, results)
        return results

    def _search_in_data(self, data: Any, keyword: str, payload_type: str, results: List[Dict[str, Any]]):
        """递归搜索数据"""
        if isinstance(data, str):
            if keyword.lower() in data.lower():
                results.append({
                    'type': payload_type,
                    'payload': data
                })
        elif isinstance(data, list):
            for item in data:
                self._search_in_data(item, keyword, payload_type, results)
        elif isinstance(data, dict):
            for key, value in data.items():
                if keyword.lower() in str(key).lower():
                    results.append({
                        'type': payload_type,
                        'section': key,
                        'payload': str(value)[:200]
                    })
                self._search_in_data(value, keyword, payload_type, results)

    def generate_payloads(self, payload_type: str, section: str, **kwargs) -> List[str]:
        """生成 payload（替换占位符）"""
        payloads = self.get_section(payload_type, section)
        result = []
        self._generate_from_template(payloads, kwargs, result)
        return result

    def _generate_from_template(self, data: Any, kwargs: Dict[str, str], result: List[str]):
        """递归生成 payload"""
        if isinstance(data, str):
            try:
                result.append(data.format(**kwargs))
            except KeyError:
                result.append(data)
        elif isinstance(data, list):
            for item in data:
                self._generate_from_template(item, kwargs, result)
        elif isinstance(data, dict):
            for value in data.values():
                self._generate_from_template(value, kwargs, result)


def main():
    """命令行入口"""
    parser = argparse.ArgumentParser(description='Hunter Payload 知识库加载器')
    parser.add_argument('--list', action='store_true', help='列出所有 payload 类型')
    parser.add_argument('--type', '-t', help='指定 payload 类型')
    parser.add_argument('--section', '-s', help='指定章节')
    parser.add_argument('--search', '-q', help='搜索关键字')
    parser.add_argument('--generate', '-g', action='store_true', help='生成 payload')
    parser.add_argument('--args', '-a', nargs='*', help='生成 payload 的参数')

    args = parser.parse_args()
    loader = PayloadLoader()

    if args.list:
        print("可用的 Payload 类型:")
        for ptype in loader.list_types():
            print(f"  - {ptype}")
        return

    if args.search:
        results = loader.search(args.search)
        if results:
            print(f"搜索结果 ({len(results)} 个):")
            for r in results:
                print(f"  [{r['type']}] {r.get('section', '')}: {r['payload'][:100]}...")
        else:
            print("未找到匹配的 payload")
        return

    if args.type:
        try:
            if args.section:
                if args.generate:
                    # 生成 payload
                    kwargs = {}
                    if args.args:
                        for arg in args.args:
                            if '=' in arg:
                                key, value = arg.split('=', 1)
                                kwargs[key] = value
                    payloads = loader.generate_payloads(args.type, args.section, **kwargs)
                    print(f"生成的 payload ({len(payloads)} 个):")
                    for p in payloads:
                        print(f"  {p}")
                else:
                    # 获取特定章节
                    section = loader.get_section(args.type, args.section)
                    print(f"{args.type}/{args.section}:")
                    print(yaml.dump(section, default_flow_style=False, allow_unicode=True))
            else:
                # 获取所有 payload
                payloads = loader.get_payloads(args.type)
                print(f"{args.type} payload 知识库:")
                print(yaml.dump(payloads, default_flow_style=False, allow_unicode=True))
        except (FileNotFoundError, KeyError) as e:
            print(f"错误: {e}")
        return

    parser.print_help()


if __name__ == '__main__':
    main()
