"""Authority readers must reject special files before waiting for any data."""

import os
import subprocess
import sys

import pytest


@pytest.mark.skipif(os.name == "nt", reason="POSIX authority readers and FIFOs")
@pytest.mark.parametrize("reader", ["inventory", "binary"])
def test_authority_reader_rejects_fifo_without_waiting(tmp_path, reader):
    code = """
import os, sys
from pathlib import Path
from z4j_brain.domain.production_container_authority import (
    _REQUIRED_FILES, _read_exact_inventory, _default_binary_reader,
    ProductionContainerAuthorityRefused,
)
root = Path(sys.argv[1])
if sys.argv[2] == 'inventory':
    for name in _REQUIRED_FILES:
        (root / name).write_bytes(b'{}')
    target = root / sorted(_REQUIRED_FILES)[0]
    target.unlink()
    os.mkfifo(target)
    run = lambda: _read_exact_inventory(root)
else:
    target = root / 'binary'
    os.mkfifo(target)
    run = lambda: _default_binary_reader(target)
try:
    run()
except ProductionContainerAuthorityRefused as exc:
    assert 'regular file' in str(exc), str(exc)
else:
    raise AssertionError('FIFO accepted')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path), reader],
        timeout=5,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode()
