import time
import asyncio
from typing import Awaitable, Callable, TypeVar

T = TypeVar("T")
MIN_NODE_SECONDS = 20.0


def enforce_min_20s_sync(fn: Callable[[], T], min_seconds: float = MIN_NODE_SECONDS) -> tuple[T, float]:
    """Executa a varredura/verificacao e garante piso minimo de 20s por no/alvo."""
    started = time.monotonic()
    result = fn()
    elapsed = time.monotonic() - started
    remaining = max(0.0, min_seconds - elapsed)
    if remaining > 0:
        time.sleep(remaining)
    total_elapsed = time.monotonic() - started
    return result, total_elapsed


async def enforce_min_20s_async(fn: Callable[[], Awaitable[T]], min_seconds: float = MIN_NODE_SECONDS) -> tuple[T, float]:
    """Versao assincrona para loops de nos/alvos com piso minimo de 20s."""
    started = time.monotonic()
    result = await fn()
    elapsed = time.monotonic() - started
    remaining = max(0.0, min_seconds - elapsed)
    if remaining > 0:
        await asyncio.sleep(remaining)
    total_elapsed = time.monotonic() - started
    return result, total_elapsed
