"""Local export authority stays with the original directory through path swaps."""

import os

import pytest
from z4j_brain.domain.export_sinks import ExportSinkError, LocalDirectorySink


async def chunks():
    yield b"export bytes"


def replaced_base(tmp_path):
    base = tmp_path / "exports"
    base.mkdir()
    sink = LocalDirectorySink(base)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.json").write_bytes(b"outside bytes")
    base.rename(tmp_path / "original-exports")
    base.symlink_to(outside, target_is_directory=True)
    return sink, outside


def test_download_refuses_replaced_base(tmp_path):
    sink, _outside = replaced_base(tmp_path)
    with pytest.raises(ExportSinkError):
        opened = sink.open_download("canary.json")
        opened.file.close()


async def test_write_refuses_replaced_base(tmp_path):
    sink, outside = replaced_base(tmp_path)
    with pytest.raises(ExportSinkError):
        await sink.write("new.json", chunks(), content_type="application/json")
    assert not (outside / "new.json").exists()


async def test_discard_cannot_delete_through_replaced_base(tmp_path):
    sink, outside = replaced_base(tmp_path)
    await sink.discard("canary.json")
    assert (outside / "canary.json").read_bytes() == b"outside bytes"


def test_download_refuses_different_directory_at_same_base_path(tmp_path):
    base = tmp_path / "exports"
    base.mkdir()
    sink = LocalDirectorySink(base)
    base.rename(tmp_path / "original-exports")
    base.mkdir()
    (base / "canary.json").write_bytes(b"replacement bytes")
    with pytest.raises(ExportSinkError):
        opened = sink.open_download("canary.json")
        opened.file.close()


async def test_stream_error_cleans_its_temporary_file(tmp_path):
    sink = LocalDirectorySink(tmp_path)

    async def fails():
        yield b"partial"
        raise RuntimeError("fixture stream interruption")

    with pytest.raises(RuntimeError, match="fixture stream interruption"):
        await sink.write("a/export.json", fails(), content_type="application/json")
    assert list((tmp_path / "a").iterdir()) == []
    result = await sink.write("a/export.json", chunks(), content_type="application/json")
    opened = sink.open_download(result.key)
    with opened.file:
        assert opened.file.read() == b"export bytes"
    await sink.discard(result.key)
    assert not (tmp_path / "a" / "export.json").exists()


async def test_concurrent_writers_publish_only_complete_files(tmp_path):
    import asyncio

    sink = LocalDirectorySink(tmp_path)
    both_started = asyncio.Event()
    started = 0

    async def stream(value):
        nonlocal started
        started += 1
        if started == 2:
            both_started.set()
        yield value
        await asyncio.wait_for(both_started.wait(), timeout=5)
        yield value

    await asyncio.gather(
        sink.write("same.json", stream(b"first"), content_type="application/json"),
        sink.write("same.json", stream(b"second"), content_type="application/json"),
    )
    assert (tmp_path / "same.json").read_bytes() in (b"firstfirst", b"secondsecond")
    assert sorted(p.name for p in tmp_path.iterdir()) == ["same.json"]


async def test_regular_replacement_at_base_is_refused_for_write_and_discard(tmp_path):
    base = tmp_path / "exports"
    base.mkdir()
    sink = LocalDirectorySink(base)
    base.rename(tmp_path / "original")
    base.mkdir()
    (base / "canary.json").write_bytes(b"keep")
    with pytest.raises(ExportSinkError):
        await sink.write("new.json", chunks(), content_type="application/json")
    await sink.discard("canary.json")
    assert (base / "canary.json").read_bytes() == b"keep"
    assert not (base / "new.json").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permits renaming held directories")
@pytest.mark.parametrize("replace_base", [False, True])
async def test_directory_swap_during_write_cannot_publish_outside(tmp_path, replace_base):
    base = tmp_path / "exports"
    base.mkdir()
    sink = LocalDirectorySink(base)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.json").write_bytes(b"outside")
    original = tmp_path / "original"

    async def swapping_chunks():
        yield b"partial"
        swapped = base if replace_base else base / "child"
        swapped.rename(original)
        swapped.symlink_to(outside, target_is_directory=True)
        yield b"end"

    with pytest.raises(ExportSinkError):
        await sink.write("child/canary.json", swapping_chunks(), content_type="application/json")
    assert (outside / "canary.json").read_bytes() == b"outside"
    assert not list(original.rglob("*.tmp"))
    assert not list(original.rglob("canary.json"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX FIFO")
def test_download_rejects_fifo_without_blocking(tmp_path):
    import subprocess
    import sys

    code = """
import os, sys
from pathlib import Path
from z4j_brain.domain.export_sinks import ExportSinkError, LocalDirectorySink
base = Path(sys.argv[1])
os.mkfifo(base / 'pipe.json')
try:
    LocalDirectorySink(base).open_download('pipe.json')
except ExportSinkError:
    pass
else:
    raise AssertionError('FIFO accepted')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(tmp_path)], timeout=10, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr.decode()


@pytest.mark.skipif(os.name != "nt", reason="Windows holds directories without delete sharing")
async def test_windows_refuses_rename_during_stream(tmp_path):
    sink = LocalDirectorySink(tmp_path)

    async def rename_attempt():
        yield b"first"
        with pytest.raises(PermissionError):
            (tmp_path / "child").rename(tmp_path / "moved")
        yield b"last"

    await sink.write("child/export.json", rename_attempt(), content_type="application/json")
    assert (tmp_path / "child/export.json").read_bytes() == b"firstlast"


async def test_cancelled_write_cleans_temporary_file(tmp_path):
    import asyncio

    sink = LocalDirectorySink(tmp_path)
    reached = asyncio.Event()

    async def waiting():
        yield b"partial"
        reached.set()
        await asyncio.Event().wait()

    writer = asyncio.create_task(
        sink.write("export.json", waiting(), content_type="application/json")
    )
    await asyncio.wait_for(reached.wait(), timeout=5)
    writer.cancel()
    with pytest.raises(asyncio.CancelledError):
        await writer
    assert list(tmp_path.iterdir()) == []
