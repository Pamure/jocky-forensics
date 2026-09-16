# Installing JOCKY

JOCKY has **no third-party dependencies** — it is Python standard library only.
That is a design constraint, not an accident: a collection tool that needs a
package index is one that fails on the host you are investigating, and an
air-gapped range is not a hypothetical for this project.

---

## 1. Requirements

| | |
|---|---|
| Python | **3.12 or newer** (`requires-python = ">=3.12"`) |
| Linux | any distribution with `/proc`, `/proc/net` and `/sys` (this is the full-capability platform) |
| Windows | Windows 10/11, any Python 3.12+ from python.org |
| Privileges | none required to install or run; some collection is wider as root/administrator |
| Disk | ~2 MB for the package |

**Nothing is installed system-wide.** The recommended flow is a virtual
environment inside a checkout, which is also what the test suite assumes.

---

## 2. Install from source (Linux)

```bash
git clone https://github.com/Pamure/jocky-forensics.git
cd jocky-forensics
python3 -m venv venv
./venv/bin/pip install -e .
./venv/bin/jocky doctor          # verify the host can run every mode
```

`jocky doctor` is the acceptance test for an install. On a healthy Linux host it
ends with:

```text
ready: 12 ok, 1 warning(s), 0 failure(s)
```

The one warning is usually *effective uid* — reading other users' `/proc`
entries needs root or `CAP_SYS_PTRACE`, and JOCKY says so rather than reporting
a clean sweep it cannot substantiate.

### Install without a virtual environment

```bash
python3 -m pip install --user -e .
~/.local/bin/jocky doctor
```

### Run without installing

The package is a plain directory; `pyproject.toml` only adds the `jocky` console
script. Adding the checkout to `PYTHONPATH` is enough:

```bash
PYTHONPATH=/path/to/jocky-forensics python3 -m jocky doctor
```

---

## 3. Install on Windows

```powershell
git clone https://github.com/Pamure/jocky-forensics.git
cd jocky-forensics
py -3 -m venv venv
venv\Scripts\pip install -e .
venv\Scripts\jocky doctor
```

Verified on Windows 11 with Python 3.13, non-elevated:

```text
[ok  ] process table (winapi)   231 process(es) via jocky.rt.winapi (Toolhelp32 + NtQuerySystemInformation)
[ok  ] network tables           135 socket(s) via jocky.rt.winapi (GetExtendedTcpTable/GetExtendedUdpTable)
[ok  ] sqlite3                  3.50.4
[warn] direct syscalls          direct syscalls are a Linux-only mechanism (sys.platform='win32')
[warn] sandbox (Landlock)       Landlock is a Linux-only mechanism
[FAIL] memfd_create             memfd_create is a Linux mechanism; fileless execution has no equivalent here
```

**The two FAILs are correct.** Fileless execution is a Linux mechanism (memfd
plus `execve` of `/proc/self/fd/N`) and has no Windows equivalent in this
runtime. Everything else — the language, the polymorphic encoder, collection,
the CI gate, the management console — works on both platforms.

### Running from WSL against Windows

If you are in WSL and want to exercise the Windows collectors, copy the package
to a Windows-visible path and invoke the Windows interpreter by its full path.
`cmd.exe` cannot start in a `\\wsl.localhost\...` directory, so the copy is
required, not optional:

```bash
cp -r jocky /mnt/c/Users/<you>/AppData/Local/Temp/jky-win/
cd /mnt/c/Users/<you>/AppData/Local/Temp/jky-win
/mnt/c/Windows/System32/cmd.exe /c "python -m jocky run script.jky"
```

---

## 4. Docker

```bash
docker build -t jocky .
docker run --rm -it --pid=host -v /proc:/proc:ro jocky doctor
docker run --rm -it -v "$PWD/case:/case" jocky init /case
```

The image deliberately does **not** install `procps`: JOCKY reads `/proc`
directly, so an image without `ps`, `ss` or `lsof` demonstrates at runtime that
collection spawns nothing. `--pid=host` is needed to see the host's process
table rather than the container's.

---

## 5. Verify the install

```bash
./venv/bin/jocky doctor          # host capability report
./venv/bin/jocky triage          # built-in triage, no script needed
./venv/bin/jocky run scripts/triage.jky --json
./venv/bin/jocky run scripts/quickstart.jky    # guided tour of the language
```

Reproduce the project's own measurements (about a minute at the default count):

```bash
./venv/bin/jocky evidence --iterations 1000 --out evidence
sed -n '1,80p' evidence/report.md
```

Run the test suites:

```bash
./venv/bin/python -m pytest tests/ -q      # behavioural suite
./venv/bin/jocky test tests/lang           # in-language assertions
./venv/bin/jocky ci --script scripts/hunt.jky --count 256   # polymorphic gate
```

---

## 6. Platform capability matrix

What each platform can actually do, as measured rather than assumed:

| Capability | Linux | Windows |
|---|---|---|
| Language, compiler, VM | yes | yes |
| Polymorphic build + artifact execution (`build`/`exec`) | yes | yes |
| CI gate (`jocky ci`) | yes | yes |
| Process / socket / driver collection | yes (`/proc`, `/proc/net`, `/sys`) | yes (`ctypes` → kernel32/ntdll/iphlpapi/psapi) |
| BYOVD / kernel-module integrity | yes | yes |
| Management server + web console | yes | yes |
| Landlock + seccomp confinement (`--sandbox`) | yes | no — reported as unenforced |
| Fileless / memfd execution | yes | no |
| Direct syscall trampoline (`mem.syscall`) | yes | no |

Where a mechanism is Linux-only, JOCKY **says so** and names the platform,
rather than reporting the feature as missing-and-installable.

---

## 7. Troubleshooting

**`jocky: command not found`** — the console script lives in the venv. Use
`./venv/bin/jocky`, or activate the venv (`source venv/bin/activate`).

**`doctor` reports `/proc missing`** — you are in a container without `/proc`
mounted. Run with `--pid=host` and `-v /proc:/proc:ro`, or run on the host.

**`doctor` reports `effective uid` warning** — expected for a normal account.
Reading other users' process details needs root or `CAP_SYS_PTRACE`. The triage
compensates: a run where part of the process table was unreadable reports a
`partial_visibility` finding, so a clean result is never mistaken for a
complete one.

**`fileless end-to-end` fails on Linux** — `memfd_create` needs kernel 3.17+ and
a kernel that does not block it. Check `uname -r`. Fileless mode is optional;
`jocky run` works regardless.

**OpenSSL not found** — `jocky serve` generates its self-signed certificate with
the `openssl` binary. Without it, supply `--cert` and `--key` explicitly. Every
other feature is unaffected. (Windows ships without `openssl` on `PATH`; this is
the one doctor warning you will normally see there.)

**The console is blank / TLS warning** — the server uses a self-signed
certificate. Your browser must accept it once. Then open
`https://<host>:<port>/` and paste the token from the `jocky serve` banner.

---

## 8. Uninstalling

Nothing is installed outside the checkout and its venv:

```bash
rm -rf venv jocky_forensics.egg-info
```

If you used `pip install --user`, remove the console script with
`python3 -m pip uninstall jocky-forensics`.
