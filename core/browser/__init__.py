"""Deferred browser automation planning primitives."""

from .browser_controller import BrowserController, ElementLocator
from .dynamic_hook_injector import DynamicHookInjector
from .session_store import BrowserSessionStore

__all__ = [
    "BrowserController",
    "BrowserSessionStore",
    "DynamicHookInjector",
    "ElementLocator",
]

try:
    from .websocket_capture import WebSocketCapture
except ModuleNotFoundError as exc:
    if exc.name != f"{__name__}.websocket_capture":
        raise
else:
    __all__.append("WebSocketCapture")
