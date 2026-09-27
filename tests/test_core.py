"""Tests for permission_mask_checker.

We create real files in tempfile directories and set their modes with os.chmod, then
assert against numeric masks. This avoids mocking os.stat, which would only test our
mocks. Filesystem mode bits are the actual behaviour we care about.

Determinism notes:
- No time, no sleeps, no floats. Every assertion is on integer bits or raised types.
- We do not assume any particular umask; we explicitly chmod every fixture to a known
  mode before asserting.
"""

import os
import tempfile
import unittest

from permission_mask_checker import (
    PermissionMaskChecker,
    PermissionMaskError,
    check_permission_mask,
)


class _TempFile:
    """Context manager that creates a temp file and chmods it to a known mode."""

    def __init__(self, mode: int) -> None:
        self.mode = mode
        self.path: str = ""

    def __enter__(self) -> str:
        fd, self.path = tempfile.mkstemp(prefix="pmc_test_")
        os.close(fd)
        os.chmod(self.path, self.mode)
        return self.path

    def __exit__(self, *exc) -> None:
        try:
            os.chmod(self.path, 0o700)  # ensure removable even if we set 0o000
            os.remove(self.path)
        except OSError:
            pass


class TestSatisfies(unittest.TestCase):
    def test_group_writable_satisfied(self):
        with _TempFile(0o660) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o020))

    def test_group_writable_not_satisfied(self):
        with _TempFile(0o644) as p:
            self.assertFalse(PermissionMaskChecker(p).satisfies(0o020))

    def test_world_readable_satisfied(self):
        with _TempFile(0o644) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o004))

    def test_world_readable_not_satisfied(self):
        with _TempFile(0o640) as p:
            self.assertFalse(PermissionMaskChecker(p).satisfies(0o004))

    def test_mask_zero_always_satisfied(self):
        with _TempFile(0o600) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o000))

    def test_multiple_required_bits_all_present(self):
        with _TempFile(0o744) as p:
            # owner-exec | world-read
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o104))

    def test_multiple_required_bits_one_missing(self):
        with _TempFile(0o740) as p:
            # owner-exec present, world-read missing
            self.assertFalse(PermissionMaskChecker(p).satisfies(0o104))

    def test_extra_bits_in_mode_are_fine(self):
        with _TempFile(0o777) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o020))

    def test_setgid_bit_required_and_present(self):
        with _TempFile(0o2755) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o2000))

    def test_setgid_bit_required_but_absent(self):
        with _TempFile(0o0755) as p:
            self.assertFalse(PermissionMaskChecker(p).satisfies(0o2000))

    def test_sticky_bit_required_and_present(self):
        with _TempFile(0o1755) as p:
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o1000))

    def test_file_type_bits_not_confused_with_perm_bits(self):
        # A regular file's st_mode includes S_IFREG (0o100000). If we failed to mask,
        # requiring 0o020 would spuriously match because 0o100000 & 0o020 == 0... but
        # more importantly, a mask like 0o100000 should NOT be treated as a permission
        # requirement. We confirm only low 12 bits matter.
        with _TempFile(0o644) as p:
            # 0o100000 is the regular-file type bit; our checker should ignore it,
            # so requiring it should not be satisfied by perm bits alone.
            # (0o100000 & 0o7777) == 0, so the effective required mask is 0 → satisfied.
            # This documents the masking behaviour explicitly.
            self.assertTrue(PermissionMaskChecker(p).satisfies(0o100000))


class TestErrors(unittest.TestCase):
    def test_missing_path_raises_permission_mask_error(self):
        # Use a path that definitely does not exist.
        missing = os.path.join(tempfile.gettempdir(), "pmc_does_not_exist_9f8a7c.txt")
        self.assertFalse(os.path.exists(missing))
        with self.assertRaises(PermissionMaskError):
            PermissionMaskChecker(missing).satisfies(0o020)

    def test_permission_mask_error_is_os_error(self):
        missing = os.path.join(tempfile.gettempdir(), "pmc_does_not_exist_2b1d3e.txt")
        with self.assertRaises(OSError):
            PermissionMaskChecker(missing).satisfies(0o020)

    def test_non_int_mask_raises_type_error(self):
        with _TempFile(0o644) as p:
            with self.assertRaises(TypeError):
                PermissionMaskChecker(p).satisfies("0o020")  # type: ignore[arg-type]

    def test_negative_mask_raises_value_error(self):
        with _TempFile(0o644) as p:
            with self.assertRaises(ValueError):
                PermissionMaskChecker(p).satisfies(-1)


class TestConvenienceFunction(unittest.TestCase):
    def test_check_permission_mask_matches_checker(self):
        with _TempFile(0o660) as p:
            self.assertTrue(check_permission_mask(p, 0o020))
        with _TempFile(0o600) as p:
            self.assertFalse(check_permission_mask(p, 0o020))

    def test_check_permission_mask_missing_path(self):
        missing = os.path.join(tempfile.gettempdir(), "pmc_does_not_exist_55aa.txt")
        with self.assertRaises(PermissionMaskError):
            check_permission_mask(missing, 0o020)


class TestModeIntrospection(unittest.TestCase):
    def test_mode_returns_low_12_bits(self):
        with _TempFile(0o0755) as p:
            self.assertEqual(PermissionMaskChecker(p).mode(), 0o0755)

    def test_mode_strips_file_type_bits(self):
        with _TempFile(0o0644) as p:
            raw = os.stat(p).st_mode
            # raw has type bits; .mode() must not.
            self.assertEqual(PermissionMaskChecker(p).mode(), raw & 0o7777)
            self.assertNotEqual(PermissionMaskChecker(p).mode(), raw)


class TestSymlinkBehaviour(unittest.TestCase):
    def test_symlink_follows_target(self):
        # We follow symlinks: the mask is checked against the target's mode.
        with _TempFile(0o660) as target:
            link = target + "_link"
            try:
                os.symlink(target, link)
                self.assertTrue(PermissionMaskChecker(link).satisfies(0o020))
            finally:
                if os.path.islink(link):
                    os.remove(link)

    def test_dangling_symlink_raises(self):
        target = os.path.join(tempfile.gettempdir(), "pmc_dangling_target.txt")
        link = os.path.join(tempfile.gettempdir(), "pmc_dangling_link.txt")
        self.assertFalse(os.path.exists(target))
        try:
            os.symlink(target, link)
            with self.assertRaises(PermissionMaskError):
                PermissionMaskChecker(link).satisfies(0o020)
        finally:
            if os.path.islink(link):
                os.remove(link)


if __name__ == "__main__":
    unittest.main()
