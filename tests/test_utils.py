"""
Utility functions and decorators for tests.
"""

import asyncio


def async_test(coro):
    """Decorator to run async tests."""

    def wrapper(*args, **kwargs):
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(coro(*args, **kwargs))

    return wrapper
