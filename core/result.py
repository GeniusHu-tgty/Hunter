"""
Result 类型 - Shannon 核心模式

统一错误处理，避免异常传播。
"""

from typing import TypeVar, Generic, Optional, Callable, Any

T = TypeVar('T')
E = TypeVar('E')


class Result(Generic[T, E]):
    """统一结果类型"""

    def __init__(self, value: Optional[T] = None, error: Optional[E] = None):
        self.value = value
        self.error = error
        self.ok = error is None

    def is_ok(self) -> bool:
        """是否成功"""
        return self.ok

    def is_err(self) -> bool:
        """是否失败"""
        return not self.ok

    def unwrap(self) -> T:
        """解包成功值，失败则抛出异常"""
        if self.ok:
            return self.value
        raise RuntimeError(f"Called unwrap on Err: {self.error}")

    def unwrap_or(self, default: T) -> T:
        """解包成功值，失败则返回默认值"""
        if self.ok:
            return self.value
        return default

    def map(self, fn: Callable[[T], Any]) -> 'Result':
        """映射成功值"""
        if self.ok:
            return Result(value=fn(self.value))
        return Result(error=self.error)

    def flat_map(self, fn: Callable[[T], 'Result']) -> 'Result':
        """扁平映射"""
        if self.ok:
            return fn(self.value)
        return Result(error=self.error)

    def __repr__(self) -> str:
        if self.ok:
            return f"Ok({self.value!r})"
        return f"Err({self.error!r})"


def ok(value: T) -> Result[T, None]:
    """创建成功结果"""
    return Result(value=value)


def err(error: E) -> Result[None, E]:
    """创建错误结果"""
    return Result(error=error)
