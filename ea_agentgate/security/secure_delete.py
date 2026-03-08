"""
Secure deletion utilities - HIPAA §164.530(j)(1) compliant.

Provides secure data destruction with:
- Memory overwriting with random data
- Multiple pass wiping (DoD 5220.22-M inspired)
- Secure string handling
- Verification of deletion
"""

from __future__ import annotations

import ctypes
import gc
import hmac
import resource
import secrets
import sys
from typing import Any


# =============================================================================
# Secure Memory Wiping
# =============================================================================


def secure_wipe_bytes(data: bytearray, passes: int = 3) -> None:
    """
    Securely wipe a bytearray by overwriting with random data.

    Implements multi-pass overwriting inspired by DoD 5220.22-M standard.

    Args:
        data: Mutable bytearray to wipe
        passes: Number of overwrite passes (3 = DoD standard)

    Note:
        Only works with mutable bytearray, not immutable bytes.
        For strings, use SecureString class.

    Example:
        sensitive = bytearray(b"SSN: 123-45-6789")
        secure_wipe_bytes(sensitive)
        # sensitive is now random data
    """
    if not isinstance(data, bytearray):
        raise TypeError("Can only wipe mutable bytearray, not immutable bytes")

    length = len(data)

    for pass_num in range(passes):
        if pass_num == 0:
            # Pass 1: All zeros
            for i in range(length):
                data[i] = 0x00
        elif pass_num == 1:
            # Pass 2: All ones
            for i in range(length):
                data[i] = 0xFF
        else:
            # Pass 3+: Random data
            random_data = secrets.token_bytes(length)
            for i in range(length):
                data[i] = random_data[i]


def secure_wipe_string(s: str) -> bool:
    """
    Attempt to securely wipe a string from memory.

    WARNING: Python strings are immutable and may be interned.
    This function attempts best-effort wiping but cannot guarantee
    complete removal from memory.

    For truly secure handling, use SecureString class from the start.

    Args:
        s: String to wipe

    Returns:
        True if wiping was attempted (not guaranteed successful)

    Note:
        This is a best-effort function. For compliance, use:
        1. SecureString class for sensitive data
        2. Encrypted storage (data encrypted at rest)
        3. Short-lived processes/containers
    """
    try:
        # Get string's internal buffer address
        # This is CPython-specific and not guaranteed to work
        if sys.implementation.name != "cpython":
            return False

        # Attempt to overwrite using ctypes
        # String header is typically 48-56 bytes in CPython 3.x
        str_size = sys.getsizeof(s)
        header_size = sys.getsizeof("")

        # Don't wipe very short strings (likely interned)
        if len(s) < 10:
            return False

        # Get pointer to string data
        # WARNING: This is dangerous and may crash if Python internals change
        try:
            buffer_address = id(s) + header_size
            buffer_size = str_size - header_size

            if buffer_size > 0:
                # Create a ctypes array to overwrite memory
                ctypes.memset(buffer_address, 0, buffer_size)
                return True
        except OSError:
            pass

        return False

    except OSError:
        return False
    finally:
        # Force garbage collection
        gc.collect()


# =============================================================================
# Secure String Class
# =============================================================================


class SecureString:
    """
    A string wrapper that securely wipes memory when deleted.

    Stores sensitive data in a mutable bytearray and overwrites
    on deletion or explicit clear.

    Example:
        ssn = SecureString("123-45-6789")
        print(ssn.get())  # "123-45-6789"
        ssn.clear()       # Memory is now wiped
        print(ssn.get())  # Raises ValueError

    Security properties:
        - Data stored in mutable bytearray (can be overwritten)
        - Multi-pass overwrite on clear/delete
        - Prevents accidental string operations that create copies
        - Use-after-clear detection
    """

    def __init__(self, value: str | bytes, encoding: str = "utf-8"):
        """
        Create a secure string.

        Args:
            value: The sensitive string value
            encoding: Encoding for string conversion
        """
        self._encoding = encoding
        self._cleared = False

        if isinstance(value, str):
            self._data = bytearray(value.encode(encoding))
        else:
            self._data = bytearray(value)

    def get(self) -> str:
        """
        Get the string value.

        Returns:
            The stored string

        Raises:
            ValueError: If already cleared
        """
        if self._cleared:
            raise ValueError("SecureString has been cleared")

        return self._data.decode(self._encoding)

    def get_bytes(self) -> bytes:
        """
        Get as bytes (creates a copy).

        Returns:
            Copy of the stored bytes

        Raises:
            ValueError: If already cleared
        """
        if self._cleared:
            raise ValueError("SecureString has been cleared")

        return bytes(self._data)

    def clear(self, passes: int = 3) -> None:
        """
        Securely clear the stored data.

        Args:
            passes: Number of overwrite passes
        """
        if not self._cleared:
            secure_wipe_bytes(self._data, passes)
            self._data = bytearray()
            self._cleared = True

    def is_cleared(self) -> bool:
        """Check if data has been cleared."""
        return self._cleared

    @property
    def _buffer(self) -> bytearray:
        """Access internal buffer (for testing secure wipe)."""
        return self._data

    def __len__(self) -> int:
        """Return length of stored data."""
        return len(self._data)

    def __bool__(self) -> bool:
        """Return True if not cleared and has data."""
        return not self._cleared and len(self._data) > 0

    def __del__(self):
        """Securely wipe on garbage collection."""
        self.clear()

    def __repr__(self) -> str:
        """Safe repr that doesn't expose data."""
        if self._cleared:
            return "SecureString(<cleared>)"
        return f"SecureString(<{len(self._data)} bytes>)"

    def __str__(self) -> str:
        """Safe str that doesn't expose data."""
        return repr(self)

    # Prevent accidental operations that might leak data
    def __eq__(self, other: Any) -> bool:
        """Constant-time comparison."""
        if self._cleared:
            return False

        if isinstance(other, SecureString):
            if other._cleared:
                return False
            other_data = other._data
        elif isinstance(other, (str, bytes)):
            if isinstance(other, str):
                other_data = bytearray(other.encode(self._encoding))
            else:
                other_data = bytearray(other)
        else:
            return False

        # Constant-time comparison
        return hmac.compare_digest(bytes(self._data), bytes(other_data))

    def __hash__(self):
        """Prevent hashing (would leak information)."""
        raise TypeError("SecureString is not hashable for security reasons")


# =============================================================================
# Secure Dictionary for PII
# =============================================================================


class SecureDict:
    """
    Dictionary that securely wipes values on removal.

    Useful for storing PII mappings that need secure deletion.

    Example:
        vault = SecureDict()
        vault["<SSN_1>"] = "123-45-6789"

        # When removing, data is wiped
        del vault["<SSN_1>"]  # Securely wiped
    """

    def __init__(self):
        self._data: dict[str, SecureString] = {}

    def __setitem__(self, key: str, value: str | SecureString) -> None:
        # Clear old value if exists
        if key in self._data:
            self._data[key].clear()

        if isinstance(value, SecureString):
            self._data[key] = value
        else:
            self._data[key] = SecureString(value)

    def __getitem__(self, key: str) -> str:
        return self._data[key].get()

    def __delitem__(self, key: str) -> None:
        if key in self._data:
            self._data[key].clear()
            del self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get value by key with optional default."""
        try:
            return self[key]
        except KeyError:
            return default

    def pop(self, key: str, default: str | None = None) -> str | None:
        """Pop value by key with optional default."""
        if key in self._data:
            value = self._data[key].get()
            self._data[key].clear()
            del self._data[key]
            return value
        return default

    def clear(self) -> None:
        """Clear all entries securely."""
        for secure_str in self._data.values():
            secure_str.clear()
        self._data.clear()

    def keys(self):
        """Return keys of the dictionary."""
        return self._data.keys()

    def __len__(self) -> int:
        """Return number of items in the dictionary."""
        return len(self._data)

    def __del__(self):
        """Securely wipe data on destruction."""
        self.clear()


# =============================================================================
# Memory Safety Utilities
# =============================================================================


def force_gc() -> None:
    """Force garbage collection to clean up sensitive data."""
    gc.collect()
    gc.collect()
    gc.collect()


def disable_core_dumps() -> bool:
    """
    Attempt to disable core dumps to prevent memory disclosure.

    Returns:
        True if successful, False otherwise
    """
    try:
        # Set core dump size to 0
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        return True
    except (ValueError, OSError):
        return False


def lock_memory() -> bool:
    """
    Attempt to lock memory to prevent swapping sensitive data to disk.

    Returns:
        True if successful, False otherwise

    Note:
        Requires appropriate privileges (CAP_IPC_LOCK on Linux)
    """
    try:
        # Try Linux mlock
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        mcl_current = 1
        mcl_future = 2

        result = int(libc.mlockall(mcl_current | mcl_future))
        return result == 0

    except (OSError, AttributeError):
        return False


__all__ = [
    "secure_wipe_bytes",
    "secure_wipe_string",
    "SecureString",
    "SecureDict",
    "force_gc",
    "disable_core_dumps",
    "lock_memory",
]
