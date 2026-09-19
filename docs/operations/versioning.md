# Versioning and releases

Three different things in this project can change incompatibly — the language
and its runtime, the artifact file format, and the HTTP management API — and they
are versioned separately. The package version is the user-facing one; the other
two have their own constants and their own failure modes.

## One source of truth

The version string lives in exactly one place:

```python
# jocky/__init__.py
__version__ = "1.3.0"
```

Everything else reads it. Nothing in the tree hardcodes a version number:

| Consumer | How it uses the string |
|---|---|
| `jocky --version` | `jocky 1.7.1` |
| `pyproject.toml` | `dynamic = ["version"]` with `[tool.setuptools.dynamic] version = { attr = "jocky.__version__" }` |
| `jocky doctor` | the `jocky package importable` check reports the version |
| `jocky serve` | the `Server:` response header and `GET /v1/health` both report it (`jocky-management/<version>`) |
| `tools/claims_audit.py` | compares it against the newest tag and reports a mismatch as a note |

**Scope note.** The terminal transcripts on this page were taken on the v1.3.0 tree and
are kept as they were measured — the numbers in them are that version's, not the current
one. What is *current* is the policy: where this page says "the package version is
1.3.0", read "the package version at the time of measurement". The live value is
`jocky/__init__.py`.

```bash
$ ./venv/bin/jocky --version
jocky 1.3.0
```

## Releases are git tags

A release is an annotated git tag on `main`, named `v<package version>`:

```bash
$ git tag --list
docs-2026-09-15
v1.1.0
v1.2.0
v1.3.0
v1.4.0
v1.5.0
v1.6.0
v1.6.1
$ git log --oneline --decorate -3 v1.3.0
df0fd63 (tag: v1.3.0) v1.3.0: agent state hardening, serve --token-file, correct syscall name
c0b862a docs: final security/limits edit from the verification pass
bc55377 (tag: docs-2026-09-15) site: docs index route rendered real markup; complete, verified production build
$ git rev-parse --short v1.3.0^{commit}
df0fd63
```

Quoting `v1.3.0` rather than `HEAD` in the log command keeps the output stable:
tags do not move, `HEAD` does. `git describe --tags` is the command to run
against the working tree when you want "tag plus commits since"; the number in
the middle changes with every commit, so record it, not this page.

The tags are annotated, so `git cat-file -t v1.3.0` answers `tag`, not `commit`.
The tag *object* and the commit it points at are different hashes — use the
dereference form when you need the commit, for example to reproduce an
investigation from source:

```bash
$ git rev-parse v1.3.0^{commit}
df0fd63d7ce8b7c264ee2712be0694b3c8bd5c70
```

The version string, the tag list in [releases.md](../project/releases.md) and the git
history are the three records of a release, and nothing generates two of them from the
third — `tools/claims_audit.py` compares the package version against the newest tag and
reports a mismatch, so a drift is visible rather than silent.

## Version metadata

There is no generated version banner: the version reaches a reader through
`jocky --version`, `jocky/__init__.py`, the tag list and `CHANGELOG.md`. Three properties
are worth knowing before you rely on any of them.

* **The tag object and the commit are different hashes.** `%(objectname:short)` on an
  annotated tag is the tag's own hash, not the commit `git log` shows; dereference with
  `v1.3.0^{commit}` when you need the commit.
* **The package version is not the artifact version.** `1.7.1` in `jocky/__init__.py` says
  nothing about `ARTIFACT_VERSION`, which has its own byte and its own policy (below).
* **A working tree between tags has no version of its own.** `jocky --version` reports the
  package string, so record `git describe --tags --dirty` beside any measurement you take
  from an untagged checkout — which is what the evidence section of this page asks for.

## Release checklist

This is the sequence the existing tags were cut with:

```bash
# 1. bump the version in jocky/__init__.py (and describe the change in the changelog)
# 2. run the suite and regenerate the measured results
./venv/bin/python -m pytest tests/ -q
./venv/bin/python -m jocky evidence --iterations 1000 --out evidence
# 3. commit, tag, push
git commit -am "release: v$(python -c 'import jocky; print(jocky.__version__)')"
git tag -a vX.Y.Z -m 'vX.Y.Z — <summary>'
git push origin main --tags
# 4. update the hand-maintained documents that state a count or a version:
#    releases.md (the new tag), and the counts in README.md and docs/EVIDENCE.md
./venv/bin/python tools/claims_audit.py     # must print "no drift"
```

Steps 2 and 4 are the ones people skip. Step 2 matters because the numbers in
`evidence/report.md` are a snapshot of one machine at one moment: a release that
changes the runtime without regenerating them ships stale measurements. Step 4
matters because `releases.md` is no longer generated from `git tag` — it is
maintained by hand, and `claims_audit.py` is the only thing that will tell you it
went stale.

One gap to be aware of: `evidence/report.md` records the host, kernel, Python
version and mode of the run, but not the package version. When you archive an
evidence bundle, record `git describe --tags` next to it yourself.

## Semantic versioning policy

`MAJOR.MINOR.PATCH` describes the package — the language, the CLI and the
runtime natives together, because the CLI is the only front door to the language
and users experience them as one thing.

* **MAJOR** — a change that breaks a script, a CLI invocation or an embedding:
  removing or renaming syntax, changing evaluation semantics, changing a native's
  arity or return shape, removing or renaming a command or flag, or raising the
  minimum Python version.
* **MINOR** — additive and compatible: a new native, a new detection check, a new
  command or flag, a new artifact transform, a new API route.
* **PATCH** — behaviour-preserving fixes: a bug fix, a performance improvement, a
  documentation or message change. A fix that changes the *findings* a script
  produces is MINOR even if the diff is one line, because downstream reports
  change.

`1.0.0` was the first release of the runtime and was never tagged — the tag list
starts at `v1.1.0`, which added the security hardening, the integrity tooling and
the release tooling; `v1.2.0` added the Landlock sandbox and this documentation
site; `v1.3.0` hardened agent state and gave `serve` a `--token-file`. The package
version says nothing about the other two contracts, on purpose.

### Artifact format

The compiled artifact has its own version byte, independent of the package
version:

```python
# jocky/poly/encoder.py
ARTIFACT_MAGIC = b"JKY1"
ARTIFACT_VERSION = 1
```

Byte 4 of every artifact is that version, and a decoder refuses anything else
rather than guessing. Flipping the byte by hand shows the contract in action:

```bash
$ ./venv/bin/jocky build scripts/smoke.jky -o /tmp/smoke.build
wrote /tmp/smoke.build (2038 bytes, sha256 346067e7fa0523d0...)
$ python3 -c "
import pathlib
raw = bytearray(pathlib.Path('/tmp/smoke.build').read_bytes())
print('magic:', bytes(raw[:4]), 'version byte:', raw[4])
raw[4] = 9
pathlib.Path('/tmp/smoke.v9.build').write_bytes(bytes(raw))"
magic: b'JKY1' version byte: 1
$ ./venv/bin/jocky exec /tmp/smoke.v9.build
jocky: JockyArtifactError: unsupported artifact version 9
$ echo $?
2
```

The same rule governs the canonical inner serialisation, `b"JKYW"` plus
`WIRE_VERSION = 1` in `jocky/poly/wire.py`. Policy: `ARTIFACT_VERSION` (and
`WIRE_VERSION`) change **only** when the byte layout changes, never because the
package version changed. You can check that claim against the history rather than
trust it — the format constant is visible at every tag:

```bash
$ for tag in v1.1.0 v1.2.0 v1.3.0; do echo -n "$tag: "; git show $tag:jocky/poly/encoder.py | grep -m1 '^ARTIFACT_VERSION'; done
v1.1.0: ARTIFACT_VERSION = 1
v1.2.0: ARTIFACT_VERSION = 1
v1.3.0: ARTIFACT_VERSION = 1
$ git show v1.1.0:jocky/poly/wire.py | grep -m1 '^WIRE_VERSION'
WIRE_VERSION = 1
```

So the artifact format did not move between 1.1.0 and 1.3.0, and a payload built
by any of them decodes under the others. A format change is a breaking change for every
artifact built by an older release, so it is announced in the release notes and
expects at least a MINOR bump of the package version.

### HTTP API

The management API is versioned in its path: every route lives under `/v1/`.
Unknown paths and unknown API versions are rejected rather than silently
interpreted:

```text
$ curl -sk -H 'X-JKY-Token: SECRET' https://127.0.0.1:8443/v2/status
{"error": "no such endpoint: /v2/status"}
HTTP 404
```

Policy: adding a field to a response, or an optional field to a request, is
compatible and stays in `/v1/`. Removing a field, changing a type, changing the
meaning of a status code, or requiring a new request field is breaking, and gets
a new prefix (`/v2/`) served alongside `/v1/` while agents migrate — agents pin a
certificate and poll on a timer, so they cannot all be upgraded in one instant.
Routes, codes and the full schema are in [management.md](management.md).

## How a user pins a version

**A built wheel.** The distribution name is `jocky-forensics` and its version is
the package version, because `pyproject.toml` reads it dynamically:

```bash
$ ./venv/bin/python -m pip wheel --no-deps -w /tmp/wheel .
  Created wheel for jocky-forensics: filename=jocky_forensics-1.3.0-py3-none-any.whl size=130580 sha256=df3c6cd89f61395b5ffbd6b1da02720a7b68e422f4f4e48cd26c087d383f9220
Successfully built jocky-forensics
$ ls /tmp/wheel
jocky_forensics-1.3.0-py3-none-any.whl
$ ./venv/bin/python -m pip install --dry-run --no-index --no-deps --ignore-installed --find-links=/tmp/wheel "jocky-forensics==1.3.0"
Looking in links: /tmp/wheel
Processing /tmp/wheel/jocky_forensics-1.3.0-py3-none-any.whl
Would install jocky-forensics-1.3.0
```

(pip also prints the ephemeral cache directory it staged the wheel in; that path
is noise. The sha256 above is of the wheel this tree produced.)

The pin is exact and enforced by pip's resolver: `==1.3.0` matches the 1.3.0
wheel and nothing else. There is no published index for this project yet
(`project.urls` in `pyproject.toml` still carries placeholder URLs), so the
wheel is the artefact you host and pin against — an internal index or a
`--find-links` directory both work.

**A git tag.** A tag is the source of truth for reproducing a case, and its
content can be inspected without touching your working tree:

```bash
$ git rev-parse v1.3.0^{commit}
df0fd63d7ce8b7c264ee2712be0694b3c8bd5c70
$ git show v1.3.0:jocky/__init__.py | sed -n '13p'
__version__ = "1.3.0"
$ git show v1.1.0:jocky/__init__.py | sed -n '13p'
__version__ = "1.1.0"
```

Building the pinned source is then `git checkout v1.3.0` followed by installing
that tree — the identity of the tag, its commit and the version string inside it
are the three things to record together.

**A container image.** The `Dockerfile` installs the tree it is given
(`RUN pip install --no-cache-dir .`), so an image's version is the checkout's
version; building is `docker build -t jocky:1.3.0 .`.

This image build is **not verified in this environment** — there is no Docker
daemon available here. What *was* checked is the two things that previously
broke it: the `Dockerfile` has no dangling line continuations (every `\` is
followed by a real instruction), and `pip` can build this project again after the
`pyproject.toml` license metadata was fixed — the same step the image runs.
Because the dependency set is empty and `procps` is deliberately absent from the
image, an image that behaves differently from the host would be obvious
immediately.

**Which string to cite.** An editable install records the version it was installed
at, so `pip show jocky-forensics` can lag the source after a version bump; the
authoritative answers come from the package and the tag:

```bash
$ ./venv/bin/jocky --version
jocky 1.3.0
$ git rev-parse --short v1.3.0^{commit}
df0fd63
```

For a report, quote the tag; for a machine, quote the wheel filename.

## Related pages

* [releases.md](../project/releases.md) — the release table.
* [CHANGELOG.md](../../CHANGELOG.md) — what changed, per version.
* [evidence.md](evidence.md) — the harness a release has to re-run.
* [management.md](management.md) — the API that carries the `/v1/` policy.
