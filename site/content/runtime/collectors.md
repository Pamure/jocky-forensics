# Collectors

JOCKY collects from the kernel's own interfaces — `/proc`, `/proc/net`, `/sys`
and plain read-only syscalls; no `ps`, `ss`, `lsof`, `lsmod`, `find` or
`sha256sum` is ever executed. The collectors live in `jocky/rt/`:

| Namespace | Module | Primary sources |
|---|---|---|
| `proc` | `jocky/rt/procfs.py` | `/proc/<pid>/{stat,cmdline,status,exe,cwd,environ,fd,maps,io,task}`, `/proc/stat` (`btime`), `/proc/uptime` |
| `net` | `jocky/rt/netfs.py` | `/proc/net/{tcp,tcp6,udp,udp6,raw,unix,dev,route}`, `/sys/class/net/<if>/*` |
| `fs` | `jocky/rt/filefs.py` | read-only syscalls (`open`, `lstat`, `scandir`, `readlink`), `/proc/mounts` for filesystem types |
| `sys` | `jocky/rt/sysinfo.py` | `/proc/{version,uptime,stat,loadavg,meminfo,cpuinfo,mounts,modules,kallsyms}`, `/sys/module`, `/etc/os-release` |

Readers tolerate races — a process that exits between two reads yields
`nil`/an empty list instead of aborting the scan. The callable surface is in the
[native API reference](/docs/runtime/api). Outputs below come from
`./venv/bin/jocky run <script>` on the development host (kernel
`6.6.87.2-microsoft-standard-WSL2`, Python 3.12.3); PIDs, byte counts and
socket totals are live host state.

## procfs — processes

### Source and returned fields

`proc.info(pid)` is the aggregate view. It reads `/proc/<pid>/stat` (split on
the **last** `)` so a `comm` containing spaces or parentheses still parses),
then `/proc/<pid>/cmdline`, `/proc/<pid>/status`, and the `exe`/`cwd` symlinks:

| Group | Fields |
|---|---|
| identity/state | `pid`, `name`, `state`, `ppid`, `pgrp`, `session`, `tty` |
| timing, memory | `utime_ticks`, `stime_ticks`, `start_ticks`, `start_epoch`, `vsize`, `rss_pages`, `rss_kb`, `vmrss_kb`, `vmsize_kb` |
| image | `exe`, `cwd`, `cmdline`, `argv` |
| credentials | `uid`, `gid` (from `Uid:`/`Gid:` in `status`) |
| derived flags | `memfd_exe` (`exe` contains `/memfd:`), `deleted_exe` (`exe` ends `(deleted)`), `suspicious_path` (`exe` under `/tmp`, `/dev/shm`, `/var/tmp`, `/run/shm`) |

`start_epoch` is `btime` (from `/proc/stat`, cached) plus
`start_ticks / SC_CLK_TCK`. The per-descriptor readers are separate calls
because each costs one file per PID:

| Call | Source | Fields |
|---|---|---|
| `proc.fds(pid[, deleted_only])` | `/proc/<pid>/fd` + `readlink` | `fd`, `target`, `deleted`, `kind` (`file`/`socket`/`pipe`/`anon`), `inode` for sockets |
| `proc.maps(pid)` | `/proc/<pid>/maps` | `start`, `end`, `size_kb`, `perms`, `offset`, `inode`, `path`, `rwx`, `memfd`, `deleted`, `anonymous` |
| `proc.threads(pid)` | `/proc/<pid>/task` | TID list, ascending |
| `proc.io(pid)` | `/proc/<pid>/io` | `rchar`, `wchar`, `syscr`, `syscw`, `read_bytes`, `write_bytes`, `cancelled_write_bytes` |
| `proc.environ(pid)` | `/proc/<pid>/environ` | NUL-split `NAME=value` list |
| `proc.cmdline(pid)`, `proc.exe(pid)` | `/proc/<pid>/{cmdline,exe}` | argv list, symlink target |
| `proc.tree()` / `proc.pids()` | derived from `stat` `ppid` / `/proc` listing | `processes` map, `children` index, `roots` / visible PIDs |

`proc.list(limit, with_fds, with_maps)` is `info()` over every visible PID;
`limit` stops the scan early. `with_fds`/`with_maps` add the two expensive views
to every entry, so they are off by default.

### The two full-`fd` sweeps

Two collectors read **every** descriptor of every process — the only
O(processes × open files) operations in the collector set:

* `proc.deleted_open()` — files unlinked from disk but still open (a payload
  held open after `unlink`). `memfd:` targets are deliberately excluded: they
  are anonymous memory objects, not deleted disk files. Repeated descriptors of
  one file collapse into a single row with `fds` and `count`.
* `proc.socket_map()` — socket inode → `{pid, fd, name}`, built from
  `socket:[inode]` symlink targets. This is the same correlation `ss -p`
  performs, without executing it; `net` uses it for attribution.

```jocky
for item in proc.deleted_open() {
  if contains("held.txt", item.path) {
    emit {"pid": item.pid, "path": item.path, "fds": item.fds, "count": item.count}
  }
}
```

```text
{"pid": 41458, "path": "/tmp/jdocs/held.txt (deleted)", "fds": [3], "count": 1}
```

### Cost, permissions and limits

* Unprivileged collection sees its own UID's processes fully; foreign
  credentials are readable only as far as the kernel's ptrace check allows
  (`CAP_SYS_PTRACE` beyond that). The readers return what the kernel gives
  them:

```jocky
emit {"pid1_exe": proc.exe(1), "pid1_io": proc.io(1),
      "pid1_environ_len": len(proc.environ(1)), "pid1_fds": len(proc.fds(1)),
      "pid1_maps": len(proc.maps(1)), "pid1_info_is_nil": proc.info(1) == nil}
```

```text
{"pid1_exe": null, "pid1_io": {}, "pid1_environ_len": 0, "pid1_fds": 0, "pid1_maps": 0, "pid1_info_is_nil": false}
```

  `stat`/`status` remain readable (`info()` is not `nil`), so a process is still
  inventoried when its `exe`, `maps`, `io` and `environ` are denied.
* No `smaps` is read: there is no PSS or per-mapping RSS accounting, and
  `proc.maps`/`proc.fds` are unbounded per PID; only `proc.list` takes a
  `limit`.
* Only `uid`, `gid`, `VmRSS` and `VmSize` are surfaced from `/proc/<pid>/status`
  (the reader also parses `Seccomp`/`NoNewPrivs` but does not expose them);
  namespaces, cgroups and capabilities are not inventoried.
* Kernel threads have an empty `cmdline`/`argv` and no readable `exe`.

### One process, end to end

```jocky
let me = proc.info(sys.pid())
emit {"pid": me.pid, "name": me.name, "state": me.state, "ppid": me.ppid,
      "threads": me.threads, "rss_kb": me.rss_kb, "uid": me.uid,
      "exe": me.exe, "cwd": me.cwd, "memfd_exe": me.memfd_exe,
      "deleted_exe": me.deleted_exe, "suspicious_path": me.suspicious_path}

let maps = proc.maps(sys.pid())
emit {"mappings": len(maps),
      "anonymous": count(maps, fn(m) { return m.anonymous }),
      "executable": count(maps, fn(m) { return m.perms[2] == "x" }),
      "first": maps[0]}

let fds = proc.fds(sys.pid())
let kinds = {}
for fd in fds { set kinds[fd.kind] = (kinds[fd.kind] or 0) + 1 }
emit {"fds": len(fds), "kinds": kinds, "sample": fds[0]}
emit {"socket_inodes": len(proc.socket_map())}
```

```text
{"pid": 47344, "name": "jocky", "state": "R", "ppid": 4219, "threads": 1, "rss_kb": 20864, "uid": 1000, "exe": "/usr/bin/python3.12", "cwd": "/home/mjonir/f/sih2026/sih148", "memfd_exe": false, "deleted_exe": false, "suspicious_path": false}
{"mappings": 96, "anonymous": 10, "executable": 17, "first": {"start": 4194304, "end": 4325376, "size_kb": 128, "perms": "r--p", "offset": 0, "inode": 11755, "path": "/usr/bin/python3.12", "rwx": false, "memfd": false, "deleted": false, "anonymous": false}}
{"fds": 14, "kinds": {"file": 12, "pipe": 2}, "sample": {"fd": 0, "target": "/dev/null", "deleted": false, "kind": "file"}}
{"socket_inodes": 253}
```

## netfs — sockets, interfaces, routes

### Source and returned fields

Sockets are read from the kernel's own tables, one row per socket:

| Call | Source | Protocol |
|---|---|---|
| `net.connections(include_unix, with_process)` | `/proc/net/tcp`, `tcp6`, `udp`, `udp6`, `raw` | all of the above |
| `net.listeners()` | filtered `tcp`/`tcp6` rows with state `0A` | TCP LISTEN |
| `net.established()` | filtered rows with state `ESTABLISHED` | TCP |
| `net.unusual_listeners()` | `listeners()` minus a baseline port set | TCP LISTEN |
| `net.by_process()` | `connections()` grouped by attributed PID | all |

An IPv4 row's address is decoded from little-endian hex (`0100007F` →
`127.0.0.1`); IPv6 rows are four little-endian 32-bit words, as the kernel
prints them. Fields: `proto`, `local_addr`, `local_port`, `remote_addr`,
`remote_port`, `state`, `uid`, `inode`, `listening`, plus `pid`/`process` when
attribution is on. `unix` rows carry `type`, `state`, `inode`, `path` instead of
addresses, and the TCP state map covers `01`–`0B`.

Attribution is one `proc.socket_map()` sweep per call, so a socket whose owner
cannot be read — or a kernel socket — reports `pid: null`.

`net.interfaces()` merges `/sys/class/net/<if>/{address,mtu,operstate,type}`
with `/proc/net/dev` counters (`rx_bytes`, `rx_packets`, `tx_bytes`,
`tx_packets`); `net.routes()` decodes `/proc/net/route` into `iface`,
`destination`, `gateway`, `mask`, `metric`, `default`, `up`.

### Cost and limits

* `connections()` with `with_process=true` costs one `readlink` per open
  descriptor of every visible process — the most expensive `net` call.
* `unix` sockets have no addresses/ports; `listening` on a unix row means
  `type == 0001` (SOCK_STREAM) with state `01`.
* The `unusual_listeners()` baseline is a fixed set (`22, 53, 80, 123, 443,
  631, 853, 3000, 3306, 5432, 6379, 8000, 8080, 8443, 9090, 27017`): anything
  else is reported, so `low` means "outside the baseline", not "malicious".
* UDP sockets are listed but never marked `listening` — the file has no such
  state; use port and `uid` instead. `/proc/net/raw` is the IPv4 raw table:
  there is no `raw6` view, and `net.routes()` is IPv4 only.
* All tables are snapshots: a connection can close between the table read and
  the descriptor sweep, in which case the row simply has no owner.

### Example: tables, derived views, interface and route

```jocky
let rows = net.connections(false, true)
let protos = {}
for row in rows { set protos[row.proto] = (protos[row.proto] or 0) + 1 }
emit {"sockets": len(rows), "by_proto": protos}

let listening = net.listeners()
emit {"listeners": len(listening), "sample": listening[0]}

let established = net.established()
emit {"established": len(established),
      "attributed": count(established, fn(c) { return c.pid != nil }),
      "sample": established[0]}

let unix_rows = net.connections(true, false)
emit {"unix_sockets": len(unix_rows) - len(rows),
      "unusual_listeners": len(net.unusual_listeners()),
      "pids_with_sockets": len(net.by_process())}

for iface in net.interfaces() {
  emit {"iface": iface.name, "mac": iface.mac, "mtu": iface.mtu, "type": iface.type}
}
for route in net.routes() { if route.default { emit route } }
```

```text
{"sockets": 93, "by_proto": {"tcp": 68, "tcp6": 2, "udp": 17, "udp6": 4, "raw": 2}}
{"listeners": 20, "sample": {"proto": "tcp", "local_addr": "0.0.0.0", "local_port": 9993, "remote_addr": "0.0.0.0", "remote_port": 0, "state": "LISTEN", "uid": 997, "inode": 2882, "listening": true, "pid": null, "process": null}}
{"established": 26, "attributed": 23, "sample": {"proto": "tcp", "local_addr": "172.20.58.180", "local_port": 34534, "remote_addr": "104.16.8.34", "remote_port": 443, "state": "ESTABLISHED", "uid": 1000, "inode": 1434549, "listening": false, "pid": 41771, "process": "npm exec vercel"}}
{"unix_sockets": 284, "unusual_listeners": 13, "pids_with_sockets": 5}
{"iface": "eth0", "mac": "00:15:5d:fd:00:18", "mtu": "1500", "type": "1"}
{"iface": "lo", "mac": "00:00:00:00:00:00", "mtu": "65536", "type": "772"}
{"iface": "wt0", "mac": "", "mtu": "1280", "type": "65534"}
{"iface": "ztu7taowkn", "mac": "b6:aa:b4:86:47:c0", "mtu": "2800", "type": "1"}
{"iface": "eth0", "destination": "0.0.0.0", "gateway": "172.20.48.1", "mask": "0.0.0.0", "metric": 0, "default": true, "up": true}
```

## filefs — files, hashes, permissions

### Source and returned fields

`filefs` is the one collector that reads no kernel pseudo-file for its core
work: hashing, metadata, magic sniffing and scanning are read-only syscalls.
`/proc/mounts` is consulted only to label a path's filesystem type.

| Call | Behaviour |
|---|---|
| `fs.hash(path)` / `fs.hash_bytes(str)` | streamed SHA-256 in 1 MiB chunks (`nil` when unreadable) / hash of a UTF-8 string |
| `fs.stat(path)` | `lstat` **plus** the flags a triage looks for |
| `fs.magic(path)` | first 16 bytes against a fixed signature table |
| `fs.scan(root, max_files, pattern, max_depth)` | bounded recursive walk |
| `fs.timeline(root, limit)` | most recently modified files first |
| `fs.special_perms(root, max_files)` | `setuid` / `setgid` / `world_writable` buckets |
| `fs.path_dirs()` | every `$PATH` entry with hijack-relevant flags |
| `fs.ld_preload()` | `/etc/ld.so.preload` contents |
| `fs.read(path, limit)` | text read (`<unreadable: OSErrorName>` on failure) |

`stat()` returns `path`, `size`, `mode`, `mode_str`, `uid`, `gid`,
`mtime`/`ctime`/`atime`, `inode`, `nlink`, `is_dir`, `is_link`, `is_file`,
`setuid`, `setgid`, `sticky`, `world_writable`, `executable`, `in_temp` and, for
symlinks, `target`. It uses `lstat`, so a symlink reports **its own** mode —
`/bin/sh` below is `0777`, which says nothing about `/usr/bin/dash`:

```jocky
emit {"sha256": fs.hash("/etc/hostname"), "magic": fs.magic("/etc/hostname")}
emit fs.stat("/bin/sh")
```

```text
{"sha256": "4953a17aabfe061ae639db95ab31765db9a466c6a005a577527da7488a62ba26", "magic": "data"}
{"path": "/bin/sh", "size": 4, "mode": "0o777", "mode_str": "lrwxrwxrwx", "uid": 0, "gid": 0, "mtime": 1711874846.0, "ctime": 1754515825.4356167, "atime": 1789492073.7794952, "inode": 2014, "nlink": 1, "is_dir": false, "is_link": true, "is_file": false, "setuid": false, "setgid": false, "sticky": false, "world_writable": true, "executable": true, "in_temp": false, "target": "dash"}
```

Magic signatures, in match order: `elf`, `pe`, `mach-o`, `mach-o-64`,
`script:<interpreter>` (shebang), `zip`, `gzip`, `bzip2`, `xz`, `7z`, `rar`,
`pdf`, `png`, `jpeg`, `sqlite`, `zstd`; anything else is `data`, an unreadable
path is `unreadable`.

### Bounds and cost

* `scan()` is depth-first with an explicit stack, capped by `max_files`
  (default 2000) and `max_depth` (default 6, root = 0). `/proc`, `/sys`, `/dev`
  and `/run` are never descended into, `pattern` is a substring match on the
  basename, and every result costs one `lstat` plus a 16-byte read for `magic`.
* `timeline()` and `special_perms()` each run their own `scan()` with a
  5000-file budget: the cost of a timeline is that scan, not `limit`. The
  library's `hash_file` accepts `algo`, `chunk` and `max_bytes`; the native
  `fs.hash` is always whole-file SHA-256.
* `path_dirs()` resolves symlinks before reading permissions (a symlink is
  always `0777`) and refuses to call a directory "world-writable" when the
  filesystem does not implement POSIX mode bits — `drvfs`, `9p`, `vboxsf`,
  `cifs`, `smb3`, `nfs`, `nfs4`, `fuse`, `fuseblk`, `ntfs`, `ntfs3` are marked
  `opaque_permissions` instead. A missing `$PATH` directory returns only
  `{path, resolved, exists: false}`: check `exists` before `fstype`/`hijackable`.

```jocky
let hits = fs.scan("/etc", 40, "passwd", 2)
emit {"scan_hits": len(hits), "paths": transform(hits, fn(e) { return e.path })}
let recent = fs.timeline("/etc", 3)
emit {"newest": transform(recent, fn(e) { return e.path })}

let perms = fs.special_perms("/usr", 3000)
emit {"setuid": len(perms.setuid), "setgid": len(perms.setgid),
      "world_writable": len(perms.world_writable),
      "suid_sample": perms.setuid[0].path}
emit {"preload": fs.ld_preload()}

let dirs = fs.path_dirs()
let missing = 0
let hijackable = 0
for d in dirs {
  if d.exists == false { set missing = missing + 1 }
  else { if d.hijackable == true { set hijackable = hijackable + 1 } }
}
emit {"path_dirs": len(dirs), "missing": missing, "hijackable": hijackable}
```

```text
{"scan_hits": 5, "paths": ["/etc/passwd-", "/etc/passwd", "/etc/security/opasswd", "/etc/pam.d/chpasswd", "/etc/pam.d/passwd"]}
{"newest": ["/etc/systemd/system/multi-user.target.wants/snap-go-11295.mount", "/etc/systemd/system/snapd.mounts.target.wants/snap-go-11295.mount", "/etc/systemd/system/snap-go-11295.mount"]}
{"setuid": 11, "setgid": 4, "world_writable": 0, "suid_sample": "/usr/bin/sudo"}
{"preload": {"path": "/etc/ld.so.preload", "exists": false, "entries": []}}
{"path_dirs": 66, "missing": 3, "hijackable": 0}
```

`export PATH` in this shell contains 66 entries, 3 of which do not exist on
disk and 0 of which are hijackable. The detection layer turns the same data into
findings — see [detection checks](/docs/runtime/detection).

## sysinfo — host inventory

### Source and returned fields

| Call | Source | Notes |
|---|---|---|
| `sys.kernel()` | `platform.uname()` + `/proc/version` | `sysname`, `release`, `version`, `machine`, `hostname`, `wsl`, `container`, `kernel_string` |
| `sys.distro()` | `/etc/os-release` | every `KEY=value` pair, quotes stripped |
| `sys.uptime()` / `sys.loadavg()` | `/proc/uptime`, `btime` from `/proc/stat` / `/proc/loadavg` | `seconds`, `boot_time` / first three floats |
| `sys.memory()` | `/proc/meminfo` | selected keys, **bytes** (kernel prints kB) |
| `sys.cpu()` | `/proc/cpuinfo` | `model` (first `model name`), `cpus` (count of `processor` lines) |
| `sys.mounts()` | `/proc/mounts` | `device`, `mountpoint`, `fstype`, `options`, `noexec`, `nosuid`, `nodev`, `readonly` |
| `sys.modules()` | `/proc/modules` | `name`, `size`, `refcount`, `dependencies`, `state`, `address` |
| `sys.hidden_modules()` | `/proc/modules` vs loadable `/sys/module` | `in_proc_not_sys`, `in_sys_not_proc` |
| `sys.users()` / `sys.kallsyms_visible()` | `/proc` scan / `/proc/kallsyms` | processes with a non-zero `tty` (`pid`, `name`, `tty`, `uid`, `start_epoch`) / true when addresses are non-zero |
| `sys.info()` | all of the above | single-call inventory used by scripts and the agent |

`sys.memory()` normalises to bytes (`MemTotal`, `MemFree`, `MemAvailable`,
`Buffers`, `Cached`, `SwapTotal`, `SwapFree`, `Dirty`, `Writeback`).

### The hidden-module diff

`/sys/module` lists every module **and** built-in kernel subsystem, while
`/proc/modules` lists only loadable ones — comparing the raw views would flag
hundreds of built-ins (`xen`, `workqueue`, …) as "hidden". JOCKY compares
`/proc/modules` against the `/sys/module` entries that carry an `initstate`
attribute (the loadable subset), normalising `-`/`_`. A name present in one view
and absent from the other is the signal: one kernel view has been tampered with.
`det.hidden_modules()` promotes it to a finding.

### Cost and limits

* Every call is a single small file read, except `sys.users()` (one `/proc`
  sweep) and `sys.info()` (all of them). `kallsyms_visible()` is false for an
  unprivileged process because the kernel zeroes the addresses:

```text
$ head -1 /proc/kallsyms
0000000000000000 A fixed_percpu_data
```

* `container()` is a marker heuristic (`/.dockerenv`, `/run/.containerenv`,
  `/proc/1/cgroup`); it does not enumerate namespaces, and `sys.modules()` is
  empty where `/proc/modules` is unreadable or module support is compiled out.

```jocky
let host = sys.info()
emit {"hostname": host.kernel.hostname, "release": host.kernel.release,
      "machine": host.kernel.machine, "wsl": host.kernel.wsl,
      "kallsyms_visible": host.kallsyms_visible, "container": host.kernel.container}
emit {"distro": host.distro.PRETTY_NAME, "cpus": host.cpu.cpus, "model": host.cpu.model}
emit {"mem_total_kb": int(host.memory.MemTotal / 1024),
      "mem_available_kb": int(host.memory.MemAvailable / 1024),
      "swap_total_kb": int(host.memory.SwapTotal / 1024)}
emit {"loadavg": host.loadavg, "uptime_s": int(host.uptime.seconds),
      "boot_time": host.uptime.boot_time, "home": host.env.HOME,
      "path_entries": len(host.env.PATH.split(":"))}

let mounts = sys.mounts()
emit {"mounts": len(mounts), "noexec": count(mounts, fn(m) { return m.noexec }),
      "nosuid": count(mounts, fn(m) { return m.nosuid })}
for m in mounts {
  if contains(m.mountpoint, ["/", "/home", "/tmp"]) {
    emit {"mountpoint": m.mountpoint, "fstype": m.fstype, "options": m.options}
  }
}
emit {"loaded_modules": len(sys.modules()), "hidden_modules": sys.hidden_modules()}
```

```text
{"hostname": "stormbreaker", "release": "6.6.87.2-microsoft-standard-WSL2", "machine": "x86_64", "wsl": true, "kallsyms_visible": false, "container": {"docker": false, "podman": false, "cgroup_hint": "0::/init.scope", "namespaced": true}}
{"distro": "Ubuntu 24.04.3 LTS", "cpus": 16, "model": "13th Gen Intel(R) Core(TM) i7-13620H"}
{"mem_total_kb": 7979192, "mem_available_kb": 3652868, "swap_total_kb": 2097152}
{"loadavg": [1.73, 1.58, 1.15], "uptime_s": 22922, "boot_time": 1789471738.0, "home": "/home/mjonir", "path_entries": 66}
{"mounts": 60, "noexec": 11, "nosuid": 24}
{"mountpoint": "/", "fstype": "ext4", "options": "rw,relatime,discard,errors=remount-ro,data=ordered"}
{"loaded_modules": 29, "hidden_modules": {"in_proc_not_sys": [], "in_sys_not_proc": []}}
```

## Cross-cutting limits

* **Linux only.** All four collectors target procfs/sysfs; the language and
  encoder are portable but there is no Windows or macOS collection path.
* **Snapshots, not streams.** Nothing here is event-driven: each call reads the
  kernel's current state, so short-lived processes and connections between two
  calls are missed. Repeat runs (see `watch.jky`) instead of expecting coverage.
  No collector writes, deletes, mounts, kills or signals anything; nothing
  requires root, and what requires privilege is reported as empty. The reads
  are the only cost: 0 child processes, 0 write-mode opens (see the
  [evidence harness](/docs/operations/evidence)).
