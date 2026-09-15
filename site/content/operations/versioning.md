# Versioning and releases

Three different things in this project can change incompatibly — the language
and its runtime, the artifact file format, and the HTTP management API — and they
are versioned separately. The package version is the user-facing one; the other
two have their own constants and their own failure modes.

## One source of truth

The version string lives in exactly one place:

```python
# jocky/__init__.py
__version__ = "1.2.0"
```

Everything else reads it. Nothing in the tree hardcodes a version number:

| Consumer | How it uses the string |
|---|---|
| `jocky --version` | `jocky 1.2.0` |
| `pyproject.toml` | `dynamic = ["version"]` with `[tool.setuptools.dynamic] version = { attr = "jocky.__version__" }` |
| `jocky doctor` | the `jocky package importable` check reports `version 1.2.0` |
| `jocky serve` | the `Server:` response header and `GET /v1/health` both report it (`jocky-management/1.2.0`) |
| `site/tools/gen_versions.py` | reads it back out of `jocky/__init__.py` with a regex and publishes it in the docs banner |

```bash
$ ./venv/bin/jocky --version
jocky 1.2.0
```

## Releases are git tags

A release is an annotated git tag on `main`, named `v<package version>`:

```bash
$ git tag --list
v1.1.0
v1.2.0
$ git describe --tags
v1.2.0
$ git log --oneline -2
fb1f261 v1.2.0: Landlock sandbox, docs site and release versioning
67d5945 JOCKY v1.1.0: forensic scripting runtime, hardening and evidence
```

The tags are annotated, so `git cat-file -t v1.2.0` answers `tag`, not `commit`.
The tag *object* and the commit it points at are different hashes — use the
dereference form when you need the commit, for example to reproduce an
investigation from source:

```bash
$ git rev-parse v1.2.0^{commit}
fb1f261830c80e8a608765cfc169527899872c2f
```

The documentation site is published from the tagged commit, so the version
banner, the releases table and the git history cannot disagree unless someone
edits generated files by hand.

## The docs version banner

`site/tools/gen_versions.py` derives everything about versions on the site. It
takes `git tag` and `jocky/__init__.py` as input and writes three outputs:

| Output | Consumed by |
|---|---|
| `site/src/lib/versions.generated.js` | `Topbar.svelte` and the landing page badge |
| `site/static/versions.json` | anything that wants the list machine-readable |
| `site/content/project/releases.md` | the generated `/docs/project/releases` page |

It runs as part of every site build — `npm run gen` calls it and then
`gen_reference.py`, and both `npm run dev` and `npm run build` call `npm run gen`
first. Run it on its own when you only want the version metadata refreshed:

```bash
$ python3 site/tools/gen_versions.py
gen_versions: current=1.2.0 tags=2 unreleased_commits=1
```

`versions.json` is what the banner actually renders:

```json
{
  "current": "1.2.0",
  "versions": [
    {
      "version": "1.2.0",
      "date": "unreleased",
      "commit": "fb1f261",
      "subject": "working tree",
      "current": true
    },
    {
      "version": "v1.1.0",
      "date": "2026-09-15",
      "commit": "a34a5f6",
      "subject": "v1.1.0 — forensic runtime hardening, integrity and installation tooling",
      "current": false
    },
    {
      "version": "v1.2.0",
      "date": "2026-09-15",
      "commit": "fb59c2d",
      "subject": "v1.2.0 — Landlock sandbox, documentation site, release versioning",
      "current": false
    }
  ]
}
```

Three things in that file are worth understanding before you trust it:

* **The `current` entry is synthetic.** The generator compares the package
  version against the newest tag *as strings*; the package says `1.2.0` and the
  tag says `v1.2.0`, so they never match and a `{"date": "unreleased",
  "subject": "working tree"}` entry is always prepended. It is the version the
  working tree declares, regardless of tagging.
* **`unreleased_commits` can be phantom.** The generator sorts tags by creation
  date and treats the first row as latest. Two tags created the same day tie, and
  in this repository the tie resolves to `v1.1.0`, so the "unreleased" diff is
  `v1.1.0..HEAD` and counts a commit that is in fact already inside `v1.2.0`.
  Read it as "commits after *some* tag", not as a release-blocking count.
* **The `Commit` column shows the tag object.** `%(objectname:short)` on an
  annotated tag is the tag's own hash (`fb59c2d` above), not `fb1f261`, the
  commit `git log` shows. Dereference with `v1.2.0^{commit}` to compare.

Two more properties matter if you edit the generator: it writes into existing
directories rather than creating them (a tree without `site/src/lib` or
`site/static` fails with `FileNotFoundError`), and it is the only writer of
`content/project/releases.md` — that page says so in its own header comment, so
hand edits there are lost on the next build.

## Release checklist

This is the sequence the `v1.1.0` and `v1.2.0` tags were cut with, and the same
one the generator prints at the bottom of the releases page:

```bash
# 1. bump the version in jocky/__init__.py (and describe the change in the changelog)
# 2. run the suite and regenerate the measured results
./venv/bin/python -m pytest tests/ -q
./venv/bin/python -m jocky evidence --iterations 1000 --out evidence
# 3. commit, tag, push
git commit -am "release: v$(python -c 'import jocky; print(jocky.__version__)')"
git tag -a vX.Y.Z -m 'vX.Y.Z — <summary>'
git push origin main --tags
# 4. rebuild the docs so the banner, the releases table and the reference pages
#    match the tag that was just pushed
cd site && npm run gen
```

Steps 2 and 4 are the ones people skip. Step 2 matters because the numbers in
`evidence/report.md` are a snapshot of one machine at one moment: a release that
changes the runtime without regenerating them ships stale measurements. Step 4
matters because `releases.md` and the reference pages are generated *outputs* —
they only reflect a new tag after the generator runs.

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

`1.0.0` was the first release of the runtime; `1.1.0` added the security
hardening, the integrity tooling and the release tooling; `1.2.0` added the
Landlock sandbox and this documentation site. The package version says nothing
about the other two contracts, on purpose.

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
wrote /tmp/smoke.build (2148 bytes, sha256 003f8b60d26494f7...)
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
package version changed — a payload built by 1.1.0 still decodes under 1.2.0
because the format did not move. A format change is a breaking change for every
artifact built by an older release, so it is announced in the release notes and
expects a MINOR bump of the package version at least.

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
Routes, codes and the full schema are in `/docs/operations/management`.

## How a user pins a version

**A built wheel.** The distribution name is `jocky-forensics` and its version is
the package version, because `pyproject.toml` reads it dynamically:

```bash
$ ./venv/bin/python -m pip wheel --no-deps -w /tmp/wheel .
...
Successfully built jocky-forensics
$ ls /tmp/wheel
jocky_forensics-1.2.0-py3-none-any.whl
$ ./venv/bin/python -m pip install --dry-run --no-index --find-links=/tmp/wheel "jocky-forensics==1.2.0"
Looking in links: /tmp/wheel
Processing /tmp/wheel/jocky_forensics-1.2.0-py3-none-any.whl
Would install jocky-forensics-1.2.0
```

The pin is exact and enforced by pip's resolver: `==1.2.0` matches the 1.2.0
wheel and nothing else. There is no published index for this project yet
(`project.urls` in `pyproject.toml` still carries placeholder URLs), so the
wheel is the artefact you host and pin against — an internal index or a
`--find-links` directory both work.

**A git tag.** The source of truth for reproducing a case:

```bash
git checkout v1.2.0
./venv/bin/python -m pip install .
./venv/bin/jocky --version
```

**A container image.** The `Dockerfile` installs the tree it is given, so the
image version is the checkout's version:

```bash
docker build -t jocky:1.2.0 .
```

The image build is not tested in this environment — the checks that were run are
that the `Dockerfile` has no dangling line continuations and that
`pip install .` now succeeds, which is what the image's `RUN` step performs.
Because the dependency set is empty, the image contains Python, `openssl`, and
JOCKY; `ps`, `ss` and `lsof` are deliberately absent, so an image that behaves
differently from the host shows up immediately.

**Which string to cite.** One caveat about the development venv: an editable
install records the version it was installed at, so `pip show jocky-forensics`
can lag the source — it reported `1.1.0` while the tree declared `1.2.0`. The
authoritative answer is always the package itself:

```bash
./venv/bin/jocky --version   # jocky 1.2.0
git describe --tags          # v1.2.0
```

For a report, quote the tag; for a machine, quote the wheel filename.

## Related pages

* `/docs/project/releases` — the generated release table.
* `/docs/project/changelog` — what changed, per version.
* `/docs/operations/evidence` — the harness a release has to re-run.
* `/docs/operations/management` — the API that carries the `/v1/` policy.
