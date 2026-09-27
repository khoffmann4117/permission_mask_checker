"""Core permission-mask checking logic.

Design decisions (stated plainly so the tests and README agree):

1. We check the *current* mode of a path on disk via os.stat(). We do not attempt to
   interpret or normalise symbolic permission strings like "g+w". The caller supplies a
   numeric mask. This keeps the surface area small and avoids the ambiguities of parsing
   symbolic notation (octal vs. decimal, leading zeros, setuid bits, etc.).

2. A mask is required bits: every bit set in the mask must also be set on the path's
   permission mode. We do not support "forbidden bits" (bits that must be *absent*) in
   this function. That is a separate concern and conflating the two led to confusing
   APIs in earlier internal tooling, so we keep them apart.

3. We mask out everything except the low 12 permission bits (setuid, setgid, sticky,
   and rwxrwxrwx). Higher bits that stat() returns (file type bits like S_IFREG) are
   *not* part of a permission check, so including them would make masks surprising.
   We explicitly AND with 0o7777 to be defensive against platforms that pack extra
   flags into st_mode.

4. If the path does not exist, we raise PermissionMaskError, not OSError. The caller
   asked "does this path's permissions satisfy this mask?"; a missing path means the
   question cannot be answered, and we want a single exception type the caller can
   catch without importing errno.

5. We follow symlinks (os.stat, not os.lstat) because the question being asked is
   about the *effective* permissions of the thing you reach through the path, not the
   link itself. If you need to check the link's own mode, call os.lstat and build the
   mask yourself; we are not going to guess.
"""

from __future__ import annotations

import os
from typing import Union

# Only the low 12 bits are permission bits: setuid/setgid/sticky (3) + rwxrwxrwx (9).
# File-type bits (S_IFMT, e.g. S_IFREG 0o100000) live above this and must be excluded,
# otherwise a mask like 0o020 would accidentally match a regular file's type bits.
_PERM_BITS = 0o7777


class PermissionMaskError(OSError):
    """Raised when a permission mask check cannot be performed.

    Subclassing OSError keeps us compatible with code that already catches OSError for
    filesystem problems, while giving callers a more specific type to catch when they
    only care about mask-check failures.
    """


class PermissionMaskChecker:
    """Check whether a path's permission bits satisfy a required mask.

    Parameters
    ----------
    path:
        Filesystem path to inspect. May be a str or bytes or os.PathLike; anything
        os.stat accepts.

    Examples
    --------
    >>> checker = PermissionMaskChecker("/tmp")
    >>> checker.satisfies(0o020)  # group-writable bit must be set
    True
    """

    def __init__(self, path: Union[str, bytes, "os.PathLike[str]"]) -> None:
        self.path = path

    def _mode(self) -> int:
        """Return the 12-bit permission mode of the path, following symlinks.

        Raises PermissionMaskError if the path does not exist or is inaccessible.
        """
        try:
            st = os.stat(self.path)
        except FileNotFoundError as exc:
            # FileNotFoundError already carries the path; rewrap to our type so
            # callers only need to catch PermissionMaskError.
            raise PermissionMaskError(str(exc)) from exc
        except OSError as exc:
            # Permission denied, too many symlinks, etc. — same rationale.
            raise PermissionMaskError(str(exc)) from exc
        return st.st_mode & _PERM_BITS

    def satisfies(self, mask: int) -> bool:
        """Return True iff every bit set in *mask* is also set on the path's mode.

        ``mask`` is interpreted as an octal permission bitmask. Only the low 12 bits
        are considered; higher bits are ignored so callers can safely pass raw octal
        literals like ``0o020`` without worrying about file-type bits.

        A mask of 0 is trivially satisfied by any existing path.
        """
        if not isinstance(mask, int):
            raise TypeError(f"mask must be an int, got {type(mask).__name__}")
        if mask < 0:
            raise ValueError(f"mask must be non-negative, got {mask}")
        mode = self._mode()
        # Required-bits semantics: (mode & mask) == mask means every required bit is
        # present. Extra bits in mode are fine. We also mask the mask itself to the
        # low 12 bits so file-type bits in the mask are silently ignored.
        mask &= _PERM_BITS
        return (mode & mask) == mask

    def mode(self) -> int:
        """Return the 12-bit permission mode of the path (for inspection/debugging)."""
        return self._mode()


def check_permission_mask(path: Union[str, bytes, "os.PathLike[str]"], mask: int) -> bool:
    """Convenience function: equivalent to ``PermissionMaskChecker(path).satisfies(mask)``.

    Provided for callers who prefer a one-shot function over holding a checker instance.
    """
    return PermissionMaskChecker(path).satisfies(mask)
