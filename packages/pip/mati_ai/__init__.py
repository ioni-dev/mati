"""
mati-ai: thin wrapper that downloads and execs the mati binary.

On first invocation the binary is not present.  _ensure_binary() fetches
the correct release tarball from GitHub, verifies it extracted correctly,
and caches the binary for all future calls.
"""

from __future__ import annotations

import os
import platform
import stat
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

__version__ = "0.1.0"

_REPO = "ioni-dev/mati"
_VERSION = "0.1.0"

# Prefer ~/.local/bin so the binary is on PATH for other tools too.
# Fall back to the package's own bin/ directory.
_LOCAL_BIN = Path.home() / ".local" / "bin"
_PKG_BIN = Path(__file__).parent / "bin"


def _get_target() -> str:
    """Return the correct release target triple for the current platform."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Darwin":
        if machine in ("arm64", "aarch64"):
            return "aarch64-apple-darwin"
        if machine in ("x86_64", "amd64"):
            return "x86_64-apple-darwin"
        raise RuntimeError(f"mati: unsupported macOS architecture: {machine}")

    if system == "Linux":
        if machine in ("arm64", "aarch64"):
            return "aarch64-unknown-linux-musl"
        if machine in ("x86_64", "amd64"):
            return "x86_64-unknown-linux-musl"
        raise RuntimeError(f"mati: unsupported Linux architecture: {machine}")

    if system == "Windows":
        raise RuntimeError(
            "mati is not supported on Windows.\n"
            "Please use WSL2 (Windows Subsystem for Linux) to run mati.\n"
            "See https://github.com/ioni-dev/mati for details."
        )

    raise RuntimeError(f"mati: unsupported platform: {system}")


def _candidate_paths() -> list[Path]:
    """Ordered list of locations where the binary may live."""
    return [_LOCAL_BIN / "mati", _PKG_BIN / "mati"]


def _find_installed_binary() -> Path | None:
    """Return the first existing, executable mati binary, or None."""
    for p in _candidate_paths():
        if p.exists() and os.access(p, os.X_OK):
            return p
    return None


def _install_binary() -> Path:
    """Download the correct release tarball and install the binary."""
    target = _get_target()
    tarball_name = f"mati-{target}.tar.gz"
    url = f"https://github.com/{_REPO}/releases/download/v{_VERSION}/{tarball_name}"

    # Prefer ~/.local/bin; fall back to the package's own bin/
    install_dir = _LOCAL_BIN
    try:
        install_dir.mkdir(parents=True, exist_ok=True)
        # Quick write-permission test
        test_file = install_dir / ".mati_write_test"
        test_file.touch()
        test_file.unlink()
    except OSError:
        install_dir = _PKG_BIN
        install_dir.mkdir(parents=True, exist_ok=True)

    binary_path = install_dir / "mati"

    print(f"mati: downloading {tarball_name}...", file=sys.stderr)

    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # urllib.request follows redirects automatically (GitHub -> S3)
        with urllib.request.urlopen(url) as response:
            with open(tmp_path, "wb") as f:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except Exception as exc:
        os.unlink(tmp_path)
        raise RuntimeError(
            f"mati: failed to download binary from {url}\n  {exc}"
        ) from exc

    print("mati: extracting binary...", file=sys.stderr)

    try:
        with tarfile.open(tmp_path, "r:gz") as tf:
            # Find the `mati` binary inside the archive (may be at root or
            # nested one directory deep, depending on how the release is built)
            members = tf.getnames()
            mati_members = [
                m for m in members
                if m == "mati" or m.endswith("/mati")
            ]
            if not mati_members:
                raise RuntimeError(
                    f"mati: tarball does not contain a 'mati' binary.\n"
                    f"  Contents: {members[:20]}\n"
                    "  Please file an issue at https://github.com/ioni-dev/mati/issues"
                )

            # Pick the shortest path (prefer root-level over nested)
            member_name = min(mati_members, key=len)
            member = tf.getmember(member_name)
            member.name = "mati"  # strip any directory prefix on extraction

            tf.extract(member, path=str(install_dir))
    except tarfile.TarError as exc:
        raise RuntimeError(f"mati: failed to extract tarball: {exc}") from exc
    finally:
        os.unlink(tmp_path)

    if not binary_path.exists():
        raise RuntimeError(
            f"mati: extraction succeeded but binary not found at {binary_path}.\n"
            "  Please file an issue at https://github.com/ioni-dev/mati/issues"
        )

    # Make executable
    binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"mati: installed successfully -> {binary_path}", file=sys.stderr)
    return binary_path


def _ensure_binary() -> Path:
    """Return path to a ready-to-exec mati binary, installing if needed."""
    binary = _find_installed_binary()
    if binary is not None:
        return binary
    return _install_binary()


def main() -> None:
    """Entry point — called by the `mati` console script."""
    try:
        binary = _ensure_binary()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)

    # Replace the current process with the real mati binary.
    # os.execv does not return on success.
    os.execv(str(binary), [str(binary)] + sys.argv[1:])
