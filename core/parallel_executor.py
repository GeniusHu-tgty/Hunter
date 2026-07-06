"""
并行执行引擎

支持多 Agent 并行执行，提升效率。
"""

import asyncio
from typing import List, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass


@dataclass
class AgentTask:
    """Agent 任务"""
    agent_name: str
    input_data: Dict[str, Any]
    priority: int = 0


class ParallelExecutor:
    """并行执行引擎"""

    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def execute_agents(
        self,
        tasks: List[AgentTask],
        agent_executor: Callable,
    ) -> Dict[str, Any]:
        """并行执行多个 Agent"""

        # 按优先级排序
        tasks.sort(key=lambda t: t.priority, reverse=True)

        # 提交所有任务
        futures = {}
        for task in tasks:
            future = self.executor.submit(
                agent_executor,
                task.agent_name,
                task.input_data,
            )
            futures[future] = task.agent_name

        # 收集结果
        results = {}
        for future in as_completed(futures):
            agent_name = futures[future]
            try:
                result = future.result()
                results[agent_name] = {
                    'success': True,
                    'result': result,
                }
            except Exception as e:
                results[agent_name] = {
                    'success': False,
                    'error': str(e),
                }

        return results

    async def execute_phase(
        self,
        phase_name: str,
        agents: List[str],
        input_data: Dict[str, Any],
        agent_executor: Callable,
    ) -> Dict[str, Any]:
        """执行整个 Phase"""

        tasks = [
            AgentTask(
                agent_name=agent,
                input_data=input_data,
                priority=i,
            )
            for i, agent in enumerate(agents)
        ]

        return await self.execute_agents(tasks, agent_executor)

    def shutdown(self):
        """关闭执行器"""
        self.executor.shutdown(wait=False)
