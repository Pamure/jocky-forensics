# Export/ingest formats JOCKY should speak in 2026

## Scope

Formats JOCKY should emit/ingest, mapped onto its finding record `{check, severity, title, evidence,
recommendation}` (`jocky/rt/detect.py:1-14,65-75`; severity order `detect.py:26`): STIX 2.1, MISP core, OpenIOC
1.1, Sigma (+Linux), YARA/YARA-X/YARA-L 2.0, OCSF. Repo facts: `file:line`; external: URL + date.

## Findings

1. **OCSF is the only surveyed format with a native host-finding shape.** `detection_finding` is class uid 4 in
   category uid 2 ⇒ `class_uid` 2004, `type_uid = class_uid*100+activity_id` (200401 = Create); requires the seven
   base-event attributes plus `finding_info` (`events/findings/detection_finding.json`;
   github.com/ocsf/ocsf-schema). **Impact:** severity and evidence map 1:1 — lossless.
2. **OCSF churns; pin the version.** 1.5.0→1.9.0 (2026-08-03) in ~18 months; `main` 1.10.0-dev; 1.9 deprecated
   `app`→`application`. **Impact:** emit `metadata.version`; one mapping table.
3. **STIX 2.1 cannot carry severity, deletion state or fds.** Current OASIS Standard (2021 FAQ) + Errata 01
   (oasis-tcs/cti-stix2 `spec/`). The `file` SCO has no `is_deleted` (zero hits in
   `spec/stix-v2.1.md`), `process` has no fd list, SDOs have no severity. Escape hatch: `x_*` custom properties;
   patterns traverse references (`[process:image_ref.name=…]`, `[file:hashes.'SHA-256'=…]`). **Impact:**
   `(deleted)` survives only in `file.name` or `x_jocky_*`; only real indicators belong in `Indicator.pattern`.
4. **Sigma emits rules, not findings; our key checks have no Linux log source.** Spec is public domain, rules are
   DRL 1.1; `rules/linux`: process_creation 122, file_event 8, network_connection 5, auditd 6 (GitHub contents API,
   2026-09-15). **Impact:** `--format sigma` needs `--check`; `deleted_open_file` is inexpressible → refuse.
5. **Sigma YAML costs code in a stdlib-only project.** pySigma/sigma-cli are LGPL-2.1 (2026-09-15). **Impact:**
   hand-written emitter; no `sigma-cli` in CI.
6. **MISP is event-centric and lossy.** Core format draft-20 (2025-11-26): four `threat_level_id` buckets
   (4 Undefined…1 High) plus `to_ids`; `process` object has pid/image/command-line/parent-*. Core
   AGPL-3.0-or-later, objects/taxonomies/galaxy CC0 or BSD-2 (misp-project.org/license/). **Impact:** info/low
   collapse; a `jocky:` taxonomy namespace is a publication commitment.
7. **YARA-L 2.0 is not emittable; classic YARA is maintenance-only.** YARA-L is UDM-bound Google SecOps
   (`meta/events/match/outcome/condition`). YARA 4.5.8 (2026-07-28, BSD-3) entered maintenance at YARA-X 1.0
   (2025-06-04; latest v1.20.0). **Impact:** emit no YARA family; target YARA-X if ever needed.
8. **OpenIOC 1.1 is a dead XML draft** (Apache-2.0, 2013 Mandiant, github.com/fireeye/OpenIOC_1.1). **Impact:**
   ingest-only, unsupported.

## Concrete improvements

**I1 — `jocky export` (M, low risk).** Subparser beside `triage` (`jocky/cli.py:211-215`):
`jocky export --format ocsf|stix21|misp|sigma --in <triage.json|-> --out - --min-severity --check` (input:
`detect.triage()` JSON, `detect.py:326-340`, or `GET /v1/findings`). New `jocky/export/` with pure
`to_ocsf/to_stix21/to_misp` + `sigma_rule_for(check)`; stdlib only.

**I2 — OCSF mapper (S, low).** `severity`→`severity_id` (info 1 … critical 5), `is_alert = severity_id>=4`,
`finding_info.title`←title, `finding_info.analytic={name: check, uid: "jocky:detect:"+check, version}`,
`finding_info.uid` = sha256(check + canonical evidence) via `evidence._hash_json` (`jocky/evidence.py:92-95`),
`recommendation`→`remediation.desc`, hostname from `sysinfo`.

| check | evidence keys | OCSF `evidences[0]` |
|---|---|---|
| `fileless_process` | pid, name, exe, cmdline, uid, start_epoch (`detect.py:88-93`) | `process{pid, name, cmd_line, user, file{name: exe, is_deleted: true}}` |
| `deleted_open_file` | pid, fd, path (`detect.py:207-211`) | `process{pid}` + `file{path, is_deleted: true}`; `fd` → `evidences[0].data` |

```json
{"class_uid":2004,"category_uid":2,"type_uid":200401,"activity_id":1,"severity_id":4,"is_alert":true,
 "metadata":{"version":"1.9.0","product":{"vendor_name":"JOCKY","name":"jocky"}},
 "finding_info":{"uid":"<sha256>","title":"process 4242 (python3) runs from memory",
   "analytic":{"name":"fileless_process","uid":"jocky:detect:fileless_process","version":"1"}},
 "evidences":[{"uid":"fileless_process:4242","process":{"pid":4242,"name":"python3","cmd_line":"python3 -c …",
   "file":{"name":"/memfd:python3 (deleted)","is_deleted":true}}}]}
```

**I3 — STIX 2.1 exporter (M, medium).** Bundle: `identity` (sensor) + `observed-data` (`first_observed`,
`last_observed`, `number_observed: 1`, `object_refs`) + `note` (title + severity) + SCOs with UUIDv5 ids (FAQ:
UUIDv5 for SCOs); fd/deletion state as `x_jocky_fd`, `x_jocky_deleted`, `x_jocky_severity`; `Indicator` only for
real patterns, e.g. `[file:name MATCHES '.*\\(deleted\\)$']`. Risk: consumers ignore `x_*`.

**I4 — Sigma generator with refusals (M, medium).** `--check fileless_process` prints
`logsource: {product: linux, category: process_creation}`, `level` from severity, ATT&CK tags; a findings file
exits 2 ("Sigma carries rules, not evidence"); `deleted_open_file`/`memfd_mapping` refused with the reason.
~80-line YAML emitter + structural check against the shipped `sigma-detection-rule-schema.json`. Risk: blind
rules false-positive on ordinary `(deleted)` names.

**I5 — Skip OpenIOC; make MISP opt-in (S, low).** One event per run, `threat_level_id` from max severity,
`to_ids: false` unless a hash, tag `jocky:check=fileless_process`.

## Verification approach

- Golden-file test on a recorded `triage --json` fixture: OCSF required attributes, monotonic `severity_id`,
  byte-stability with an injectable clock, stable `finding_info.uid`.
- Throwaway venv (never a committed dep): validate OCSF class JSON, STIX (`stix2-validator` + `stix2.parse`),
  Sigma (`sigma-cli convert -t splunk`), MISP (`pymisp`); then `serve`→`agent --once`→`GET /v1/findings`→
  `export --format ocsf` end to end.

## Citations

OCSF github.com/ocsf/ocsf-schema (Apache-2.0; 1.9.0 2026-08-03) · STIX oasis-tcs/cti-stix2 + cti-documentation FAQ
(2021) · MISP misp-standard.org/rfc/misp-standard-core.txt (draft-20, 2025-11-26), misp-project.org/license/ ·
Sigma SigmaHQ/{sigma-specification,sigma,pySigma} (LGPL-2.1) · YARA
virustotal.github.io/yara-x/blog/yara-x-is-stable/ (2025-06-04), GitHub releases 4.5.8 / v1.20.0 · YARA-L
docs.cloud.google.com/chronicle/docs/yara-l/getting-started · OpenIOC github.com/fireeye/OpenIOC_1.1. Accessed
2026-09-15.
