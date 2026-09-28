# Permission Mask Checker

Checks whether a path's permission bits satisfy a required numeric mask, such as group-writable (`0o020`) or world-readable (`0o004`). Standard library only.

## Usage

```python
from permission_mask_checker import PermissionMaskChecker, check_permission_mask

# One-shot function
assert check_permission_mask("/tmp", 0o020) is True   # group-writable?

# Object form, if you want to inspect the mode too
c = PermissionMaskChecker("/etc/passwd")
assert c.satisfies(0o004) is True                       # world-readable?
print(oct(c.mode()))                                     # e.g. 0o644
```

Exported names: `PermissionMaskChecker`, `PermissionMaskError`, `check_permission_mask`.

## Why

Internal tooling kept reinventing the same `os.stat(path).st_mode & mask == mask` one-liner, and every copy got a different detail wrong: some forgot to strip file-type bits, some raised `FileNotFoundError` when the caller expected a single exception, some checked forbidden bits and required bits in the same flag. This library is that one-liner with the details fixed once.

The trade-off: masks are numeric only. There is no parser for symbolic strings like `g+w`. Symbolic notation has too many ambiguous forms (octal-looking decimals, setuid shorthand, combined allow/deny) to support without guessing; a numeric mask is unambiguous and matches what `chmod` accepts.

## Edge cases you will hit

- **Missing path.** Raises `PermissionMaskError` (a subclass of `OSError`), not `FileNotFoundError`. Catch `PermissionMaskError` for mask-check failures; catch `OSError` if you also want other filesystem errors.
- **Symlinks are followed.** The mask is checked against the *target's* mode, not the link's. A dangling symlink raises `PermissionMaskError`.
- **Only the low 12 bits matter.** File-type bits (e.g. `S_IFREG`) in the mask are silently ignored. Requiring `0o100000` is equivalent to requiring `0o000`, which is always satisfied by any existing path.
- **Mask of zero** is trivially satisfied by any existing path.

## Running the tests

```
PYTHONPATH=src python -m unittest discover -s tests
```
