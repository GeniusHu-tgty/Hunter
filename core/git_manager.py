"""
Git 检查点管理

支持：
- 创建检查点
- 失败回滚
- 成功提交
"""

import asyncio
from typing import Optional


class GitManager:
    """Git 检查点管理"""

    def __init__(self, repo_path: str):
        self.repo_path = repo_path

    async def create_checkpoint(self, message: str = "Hunter checkpoint") -> str:
        """创建 Git 检查点"""
        # 添加所有文件
        await self._run_git(["add", "."])

        # 提交
        commit_hash = await self._run_git([
            "commit", "-m", message, "--allow-empty"
        ])

        return commit_hash.strip()

    async def rollback(self, commit_hash: str):
        """回滚到检查点"""
        await self._run_git(["reset", "--hard", commit_hash])

    async def commit_success(self, agent_name: str, result: str):
        """成功提交"""
        message = f"Hunter: {agent_name} completed successfully"
        await self._run_git(["add", "."])
        await self._run_git(["commit", "-m", message])

    async def get_commit_hash(self) -> str:
        """获取当前提交哈希"""
        return await self._run_git(["rev-parse", "HEAD"])

    async def _run_git(self, args: list) -> str:
        """执行 Git 命令"""
        proc = await asyncio.create_subprocess_exec(
            "git", *args,
            cwd=self.repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"Git command failed: {stderr.decode()}")

        return stdout.decode()
