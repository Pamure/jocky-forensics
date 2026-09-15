"""
``jocky`` command line.

    jocky run   <script.jky>            execute a script
    jocky exec  <artifact.jky>          execute a polymorphic build
    jocky build <script.jky> -o out.jky compile to a polymorphic artifact
    jocky memfd <script.jky>            execute with no on-disk program text
    jocky disasm <script.jky>           show the bytecode
    jocky triage [--deep]               built-in host triage
    jocky info                          host inventory as JSON
    jocky evidence --iterations N       run the proof harness
    jocky serve / jocky agent           central management
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Iterable, List, Optional

from jocky import __version__
from jocky import runner
from jocky.errors import JockyRuntimeError
from jocky.lang.vm import to_plain


def _emit(payload: object, as_json: bool, text: str = "") -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))
    elif text:
        print(text)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


# ------------------------------------------------------------------ commands
def _print_findings(findings: Iterable[Any]) -> None:
    """Print findings the same way the ``--json`` path serialises them.

    The terminal view used to fall back to ``str()`` for non-container values
    and ``json.dumps(..., default=str)`` inside containers, so a finding holding
    a function printed a full dataclass repr (including VM internals) on the
    terminal and ``<fn <lambda>>`` through ``--json``. Both go through
    ``to_plain`` now; bare strings still print unquoted so existing transcripts
    stay valid.
    """
    for finding in findings:
        plain = to_plain(finding)
        print(json.dumps(plain, ensure_ascii=False, default=str)
              if isinstance(plain, (dict, list)) else plain)


def _ndjson_finding(value: Any) -> None:
    """Write one finding as it is emitted — the ``--ndjson`` sink."""
    print(json.dumps({"kind": "finding", "value": to_plain(value)},
                     ensure_ascii=False, default=str))


def _stamped_sink(now: float):
    """A sink that anchors each finding as it *arrives*.

    The post-run `stamp_findings` pass cannot help a streamed run: the findings
    left the process before it runs. One timestamp is captured up front, so
    every finding of the run still shares the same collection moment.
    """
    def sink(value: Any) -> None:
        if isinstance(value, dict):
            value.setdefault("ts", now)
        _ndjson_finding(value)
    return sink


def _run_sink(args: argparse.Namespace):
    """The sink for this invocation, or None when findings must be retained."""
    if not args.ndjson:
        return None
    if args.stamp_findings:
        return _stamped_sink(round(time.time(), 3))
    return _ndjson_finding


def _print_ndjson(result: Any) -> None:
    """Stream a run as one JSON object per line.

    With a sink installed (`--ndjson`), findings left the process as they were
    emitted and `result.findings` is empty; without one, a caller that kept
    them in memory (`--json`) still gets them printed here before the summary.
    """
    for finding in result.findings:
        _ndjson_finding(finding)
    for line in result.output:
        print(json.dumps({"kind": "output", "value": line}, ensure_ascii=False))
    for error in result.errors:
        print(json.dumps({"kind": "error", "value": error}, ensure_ascii=False))
    for check in result.checks:
        print(json.dumps({"kind": "check", **check}, ensure_ascii=False, default=str))
    print(json.dumps({
        "kind": "summary",
        "findings": result.finding_count or len(result.findings),
        "errors": len(result.errors),
        "checks": len(result.checks),
        "denials": result.denials,
        "permissions": result.permissions,
        "steps": result.steps,
        "native_calls": result.native_calls,
        "duration_ms": round(result.duration_ms, 3),
        "truncated": result.truncated,
    }, ensure_ascii=False, default=str))


def cmd_run(args: argparse.Namespace) -> int:
    source = _read(args.script)
    try:
        ctx = runner.policy_ctx(args.allow)
    except ValueError as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    result = runner.run_source(source, wall_clock_ms=args.wall_ms,
                               max_steps=args.max_steps, ctx=ctx,
                               sandbox=args.sandbox,
                               emit_sink=_run_sink(args))
    if args.stamp_findings:
        runner.stamp_findings(result.findings)
    if args.ndjson:
        _print_ndjson(result)
    elif args.json:
        _emit(result.to_dict(), True)
    else:
        _print_findings(result.findings)
        for line in result.output:
            print(line)
    for error in result.errors:
        print(f"error: {error}", file=sys.stderr)
    return 0 if not result.errors else 1


def cmd_exec(args: argparse.Namespace) -> int:
    with open(args.artifact, "rb") as fh:
        artifact = fh.read()
    if args.inspect:
        _emit(runner.inspect_artifact(artifact), True)
        return 0
    try:
        ctx = runner.policy_ctx(args.allow)
    except ValueError as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    result = runner.run_artifact(artifact, wall_clock_ms=args.wall_ms, ctx=ctx,
                                 sandbox=args.sandbox, max_steps=args.max_steps,
                                 emit_sink=_run_sink(args))
    if args.stamp_findings:
        runner.stamp_findings(result.findings)
    _emit(result.to_dict(), True) if (args.json and not args.ndjson) else None
    if args.ndjson:
        _print_ndjson(result)
    elif not args.json:
        _print_findings(result.findings)
        print(f"# {runner.result_summary(result)}", file=sys.stderr)
    return 0 if not result.errors else 1


def cmd_build(args: argparse.Namespace) -> int:
    source = _read(args.script)
    try:
        seed = bytes.fromhex(args.seed_hex) if args.seed_hex else None
    except ValueError:
        print("jocky: --seed-hex must be hexadecimal", file=sys.stderr)
        return 2
    build_kwargs = {"seed": seed, "deterministic": args.deterministic}
    if args.repeat > 1:
        infos: List[dict] = []
        for _ in range(args.repeat):
            artifact, meta = runner.build_artifact(source, **build_kwargs)
            meta["size"] = len(artifact)
            infos.append(meta)
        hashes = {m.get("artifact_hash") or m.get("build_hash") for m in infos}
        _emit({"builds": len(infos), "unique_hashes": len(hashes),
               "sizes": sorted({m["size"] for m in infos}),
               "sample": infos[0]}, True)
        return 0
    artifact, meta = runner.build_artifact(source, **build_kwargs)
    out = args.output or (args.script.rsplit(".", 1)[0] + ".jky.build")
    with open(out, "wb") as fh:
        fh.write(artifact)
    meta["path"] = out
    meta["size"] = len(artifact)
    digest = meta.get("artifact_hash", meta.get("build_hash", ""))
    _emit(meta, args.json if args.json else False,
          text=f"wrote {out} ({len(artifact)} bytes, sha256 {digest[:16]}...)")
    return 0


def cmd_fileless(args: argparse.Namespace) -> int:
    outcome = runner.fileless_run_file(args.script, wall_clock_ms=args.wall_ms,
                                       timeout=args.timeout, allow=args.allow,
                                       private=args.private)
    result = outcome.get("result") or {}
    if args.stamp_findings:
        runner.stamp_findings(result.get("findings") or [])
    if args.json:
        _emit(outcome, True)
    else:
        _print_findings(result.get("findings", []))
        evidence = outcome.get("evidence", {})
        print(f"# exit={outcome.get('exit_code')} exe={evidence.get('exe')} "
              f"memfd_maps={evidence.get('memfd_map_count')} "
              f"pid={outcome.get('pid')} {outcome.get('duration_ms', 0):.0f} ms",
              file=sys.stderr)
    if outcome.get("stderr"):
        print(outcome["stderr"], file=sys.stderr)
    return 0 if outcome.get("ok") else 1


def cmd_disasm(args: argparse.Namespace) -> int:
    print(runner.disassemble(_read(args.script)))
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    from jocky.rt import sysinfo
    _emit(sysinfo.info(), True)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from jocky.rt import detect
    report = detect.triage(deep=args.deep)
    if args.stamp_findings:
        runner.stamp_findings(report["findings"])
    if args.json:
        _emit(report, True)
        return 0
    counts = ", ".join(f"{k}={v}" for k, v in report["counts"].items() if v)
    print(f"# {counts or 'no findings'}  ({report['duration_ms']:.1f} ms, "
          f"{report['scanned']['processes']} processes)")
    for item in report["findings"]:
        print(f"[{item['severity']:<8}] {item['title']}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    from jocky.diagnostics import format_report, run_checks
    report = run_checks(quick=args.quick)
    if args.json:
        _emit(report.to_dict(), True)
    else:
        print(format_report(report))
    return 0 if report.ok else 1


def cmd_init(args: argparse.Namespace) -> int:
    from jocky.scaffold import init_project
    summary = init_project(args.directory, force=args.force)
    if args.json:
        _emit(summary, True)
        return 0
    print(f"initialised {summary['directory']}")
    for path in summary["created"]:
        print(f"  + {path}")
    for path in summary["skipped"]:
        print(f"  = {path} (exists; use --force to overwrite)")
    print("\nnext steps:")
    print("  jocky doctor")
    print("  jocky run scripts/triage.jky")
    return 0


def cmd_examples(args: argparse.Namespace) -> int:
    from jocky.scaffold import example_scripts
    scripts = example_scripts()
    if args.json:
        _emit(scripts, True)
        return 0
    for item in scripts:
        print(f"{item['name']:<14} {item['description']}")
    print(f"\n{len(scripts)} bundled example(s); copy them into a case directory with `jocky init <dir>`")
    return 0


def cmd_attest(args: argparse.Namespace) -> int:
    from jocky import case
    summary = case.attest(args.directory, note=args.note, anchor=args.anchor)
    if args.json:
        _emit(summary, True)
    else:
        print(f"attested {summary['file_count']} file(s), {summary['total_bytes']} bytes")
        print(f"  chain head {summary['chain_head']}")
        print(f"  manifest   {summary['manifest']}")
        print(f"  head       {summary['head']}")
        if summary.get("anchor"):
            print(f"  anchor     {summary['anchor']}  (keep this off-host)")
        print("\nnext: jocky sign <dir> --key-file <key>   # authenticate the head")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from jocky import case
    from jocky.canon import load_key
    try:
        key = load_key(args.key_file) if (args.key_file or os.environ.get("JOCKY_EVIDENCE_KEY")) else None
    except OSError as exc:
        print(f"jocky: cannot read key: {exc}", file=sys.stderr)
        return 2
    result = case.verify(args.directory, key=key, anchor=args.anchor)
    if args.json:
        _emit(result, True)
    else:
        state = "verified" if result["ok"] else "FAILED"
        print(f"{state}: {result.get('checked', 0)} file(s) checked in {result['directory']}")
        for key_name in ("missing", "modified", "added"):
            for path in result.get(key_name) or []:
                print(f"  {key_name}: {path}")
        for error in result.get("errors") or []:
            print(f"  {error}")
        if result.get("signature_valid") is not None:
            print(f"  signature: {'valid' if result['signature_valid'] else 'INVALID'}")
    return 0 if result["ok"] else 1


def cmd_sign(args: argparse.Namespace) -> int:
    from jocky import case
    try:
        record = case.sign_head(args.directory, key_source=args.key_file)
    except (ValueError, FileNotFoundError) as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _emit(record, True)
    else:
        print(f"signed {record['directory']} with key {record['key_id']}")
        print(f"  algorithm {record['algorithm']}")
        print(f"  signature {record['signature']}")
        print("\nverify with: jocky verify <dir> --key-file <key>")
    return 0


def cmd_sigma(args: argparse.Namespace) -> int:
    """Evaluate a Sigma rule against a log file, line by line."""
    from jocky.rt import sigma as sigma_mod

    try:
        rule = sigma_mod.load_rule(_read(args.rule), source=args.rule)
    except JockyRuntimeError as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    try:
        handle = open(args.input, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"jocky: cannot read {args.input}: {exc.strerror or exc}", file=sys.stderr)
        return 2

    findings: List[Dict[str, Any]] = []
    scanned = 0
    with handle:
        for number, line in enumerate(handle, start=1):
            scanned += 1
            text = line.rstrip("\r\n")
            if not text:
                continue
            record: Any = text
            if text.startswith("{"):
                # JSON records (Zeek/Suricata/Windows event exports) give the
                # rule real fields; anything else is matched as text.
                try:
                    decoded = json.loads(text)
                    if isinstance(decoded, dict):
                        record = decoded
                except json.JSONDecodeError:
                    pass
            if rule.matches(record):
                findings.append({"kind": "sigma_match", **rule.summary(),
                                 "line_no": number, "line": text[:400]})
                if len(findings) >= args.limit:
                    break
    if args.stamp_findings:
        runner.stamp_findings(findings)
    summary = {"rule": rule.title, "id": rule.rule_id, "level": rule.level,
               "lines": scanned, "matches": len(findings)}
    if args.json:
        _emit({"summary": summary, "findings": findings}, True)
    else:
        print(f"# {summary['matches']} match(es) in {summary['lines']} line(s) "
              f"for {rule.title!r} [{rule.level}]")
        for finding in findings:
            print(f"[{rule.level:<8}] line {finding['line_no']}: {finding['line']}")
    return 0 if not findings else 1


def cmd_yara(parser_args: argparse.Namespace) -> int:
    """Scan a file with a YARA rule (the subset this runtime implements)."""
    from jocky.rt import yararules

    try:
        rule = yararules.load_rule(_read(parser_args.rule))
    except JockyRuntimeError as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    try:
        with open(parser_args.target, "rb") as handle:
            if parser_args.offset:
                handle.seek(parser_args.offset)
            data = handle.read(parser_args.limit).decode("latin-1")
    except OSError as exc:
        print(f"jocky: cannot read {parser_args.target}: {exc.strerror or exc}",
              file=sys.stderr)
        return 2
    matched = rule.matches(data)
    findings: List[Dict[str, Any]] = []
    if matched:
        findings.append({"kind": "yara_match", **rule.summary(),
                         "path": parser_args.target, "scanned_bytes": len(data)})
        if parser_args.stamp_findings:
            runner.stamp_findings(findings)
    if parser_args.json:
        _emit({"matched": matched, "rule": rule.name, "findings": findings}, True)
    else:
        print(f"{'MATCH' if matched else 'no match'}: {rule.name} "
              f"({len(data)} bytes of {parser_args.target})")
        for finding in findings:
            print(f"[{rule.name}] {finding['path']}")
    return 1 if matched else 0


def cmd_test(args: argparse.Namespace) -> int:
    from jocky import testrunner
    try:
        summary = testrunner.run(args.path, pattern=args.pattern, wall_ms=args.wall_ms,
                                 sandbox=args.sandbox, allow=args.allow)
    except FileNotFoundError as exc:
        print(f"jocky: {exc}", file=sys.stderr)
        return 2
    if args.json:
        _emit(summary, True)
    else:
        print(testrunner.format_report(summary, verbose=args.verbose))
    return 0 if summary["ok"] else 1


def cmd_evidence(args: argparse.Namespace) -> int:
    from jocky import evidence
    report = evidence.run_all(iterations=args.iterations, out_dir=args.out,
                              quick=args.quick)
    _emit(report, True)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from jocky.agent import server
    token = args.token or os.environ.get("JOCKY_TOKEN")
    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            print(f"jocky: cannot read --token-file: {exc}", file=sys.stderr)
            return 2
    return server.serve(host=args.host, port=args.port, token=token,
                        cert=args.cert, key=args.key, state_dir=args.state)


def cmd_agent(args: argparse.Namespace) -> int:
    from jocky.agent import client
    token = args.token or os.environ.get("JOCKY_TOKEN")
    if args.token_file:
        try:
            with open(args.token_file, "r", encoding="utf-8") as handle:
                token = handle.read().strip()
        except OSError as exc:
            print(f"jocky: cannot read --token-file: {exc}", file=sys.stderr)
            return 2
    if not token:
        print("jocky: no token: pass --token, --token-file or set JOCKY_TOKEN", file=sys.stderr)
        return 2
    if args.insecure:
        print("jocky: WARNING --insecure disables certificate pinning; the token is exposed "
              "to anyone who answers that socket", file=sys.stderr)
    return client.run(server=args.server, token=token,
                      interval=args.interval, once=args.once, name=args.name,
                      state_dir=args.state, insecure=args.insecure, pin=args.pin,
                      sni=args.sni, verify_ca=args.verify_ca)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jocky",
                                     description="JOCKY forensic scripting runtime (SIH26148)")
    parser.add_argument("--version", action="version", version=f"jocky {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="execute a JOCKY script",
        epilog="Examples:\n"
               "  jocky run scripts/triage.jky          # human-readable triage\n"
               "  jocky run scripts/hunt.jky --json      # machine-readable output\n"
               "  jocky run hunt.jky --sandbox ro        # Landlock read-only confinement\n"
               "  jocky run - < myscript.jky             # read from stdin",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_run.add_argument("script")
    p_run.add_argument("--json", action="store_true")
    p_run.add_argument("--ndjson", action="store_true",
                       help="stream findings as one JSON object per line as they are "
                            "emitted (no single JSON document, findings not retained)")
    p_run.add_argument("--stamp-findings", action="store_true",
                       help="add a `ts` (epoch seconds) to every finding map that lacks one")
    p_run.add_argument("--wall-ms", type=float, default=runner.DEFAULT_WALL_MS)
    p_run.add_argument("--max-steps", type=int, default=runner.DEFAULT_MAX_STEPS)
    p_run.add_argument("--allow", default=None,
                       help="grant privileged capabilities (comma list: syscall,exec)")
    p_run.add_argument("--sandbox", default="off", choices=["off", "vm", "ro", "strict"],
                       help="Landlock confinement level for the script (default: off)")
    p_run.set_defaults(func=cmd_run)

    p_exec = sub.add_parser("exec", help="execute a compiled artifact",
        epilog="Examples:\n"
               "  jocky exec payload.jky.build --json\n"
               "  jocky exec payload.jky.build --inspect   # show artifact metadata only",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_exec.add_argument("artifact")
    p_exec.add_argument("--json", action="store_true")
    p_exec.add_argument("--ndjson", action="store_true",
                        help="stream findings as one JSON object per line as they are "
                            "emitted (no single JSON document, findings not retained)")
    p_exec.add_argument("--stamp-findings", action="store_true",
                        help="add a `ts` (epoch seconds) to every finding map that lacks one")
    p_exec.add_argument("--max-steps", type=int, default=runner.DEFAULT_MAX_STEPS,
                        help="instruction budget for an artifact you did not read "
                             "(default: 50M)")
    p_exec.add_argument("--inspect", action="store_true")
    p_exec.add_argument("--wall-ms", type=float, default=runner.DEFAULT_WALL_MS)
    p_exec.add_argument("--allow", default=None,
                        help="grant privileged capabilities (comma list: syscall,exec)")
    p_exec.add_argument("--sandbox", default="off", choices=["off", "vm", "ro", "strict"],
                        help="Landlock confinement level for the artifact (default: off)")
    p_exec.set_defaults(func=cmd_exec)

    p_build = sub.add_parser("build", help="compile a script to a polymorphic artifact",
        epilog="Examples:\n"
               "  jocky build scripts/hunt.jky -o /tmp/hunt.build\n"
               "  jocky build scripts/hunt.jky --repeat 100 --json   # uniqueness test",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_build.add_argument("script")
    p_build.add_argument("-o", "--output")
    p_build.add_argument("--repeat", type=int, default=1,
                         help="build N times and report hash uniqueness")
    p_build.add_argument("--deterministic", action="store_true",
                         help="reproduce identical bytes from --seed-hex (no per-build entropy)")
    p_build.add_argument("--seed-hex", default=None,
                         help="build seed as hex (with --deterministic for reproducible output)")
    p_build.add_argument("--json", action="store_true")
    p_build.set_defaults(func=cmd_build)

    for alias in ("fileless", "memfd"):
        p_fl = sub.add_parser(alias, help="run with nothing written to disk")
        p_fl.add_argument("script")
        p_fl.add_argument("--json", action="store_true")
        p_fl.add_argument("--wall-ms", type=float, default=runner.DEFAULT_WALL_MS)
        p_fl.add_argument("--timeout", type=float, default=120.0)
        p_fl.add_argument("--allow", default=None,
                          help="grant privileged capabilities (comma list: syscall,exec)")
        p_fl.add_argument("--private", action="store_true",
                          help="hide /proc state from other same-uid processes "
                               "(also hides the process from your own triage)")
        p_fl.add_argument("--stamp-findings", action="store_true",
                          help="add a `ts` (epoch seconds) to every finding map that lacks one")
        p_fl.set_defaults(func=cmd_fileless)

    p_disasm = sub.add_parser("disasm", help="show compiled bytecode")
    p_disasm.add_argument("script")
    p_disasm.set_defaults(func=cmd_disasm)

    p_info = sub.add_parser("info", help="host inventory")
    p_info.set_defaults(func=cmd_info)

    p_doctor = sub.add_parser("doctor", help="verify this host can run every mode")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.add_argument("--quick", action="store_true",
                          help="skip the end-to-end fileless probe")
    p_doctor.set_defaults(func=cmd_doctor)

    p_init = sub.add_parser("init", help="scaffold a case directory with runnable scripts")
    p_init.add_argument("directory", nargs="?", default=".")
    p_init.add_argument("--force", action="store_true", help="overwrite existing files")
    p_init.add_argument("--json", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_examples = sub.add_parser("examples", help="list bundled example scripts")
    p_examples.add_argument("--json", action="store_true")
    p_examples.set_defaults(func=cmd_examples)

    p_triage = sub.add_parser("triage", help="built-in host triage (no script needed)",
        epilog="Examples:\n"
               "  jocky triage                # quick human-readable summary\n"
               "  jocky triage --json         # machine-readable findings\n"
               "  jocky triage --deep --json  # deep scan (more checks, slower)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_triage.add_argument("--deep", action="store_true")
    p_triage.add_argument("--json", action="store_true")
    p_triage.add_argument("--stamp-findings", action="store_true",
                          help="add a `ts` (epoch seconds) to every finding map that lacks one")
    p_triage.set_defaults(func=cmd_triage)

    p_sigma = sub.add_parser("sigma", help="evaluate a Sigma rule against a log file")
    p_sigma.add_argument("rule", help="path to a Sigma rule (.yml)")
    p_sigma.add_argument("input", help="log file: one record per line (JSON lines give "
                                       "the rule real fields, anything else is matched as text)")
    p_sigma.add_argument("--json", action="store_true")
    p_sigma.add_argument("--limit", type=int, default=1000,
                         help="stop after this many matches (default: 1000)")
    p_sigma.add_argument("--stamp-findings", action="store_true",
                         help="add a `ts` (epoch seconds) to every finding map that lacks one")
    p_sigma.set_defaults(func=cmd_sigma)

    p_yara = sub.add_parser("yara", help="scan a file with a YARA rule (subset)")
    p_yara.add_argument("rule", help="path to a YARA rule (.yar)")
    p_yara.add_argument("target", help="file to scan (bytes are read as-is)")
    p_yara.add_argument("--offset", type=int, default=0)
    p_yara.add_argument("--limit", type=int, default=32 * 1024 * 1024,
                        help="bytes to read from the target (default: 32 MiB)")
    p_yara.add_argument("--json", action="store_true")
    p_yara.add_argument("--stamp-findings", action="store_true")
    p_yara.set_defaults(func=cmd_yara)

    p_test = sub.add_parser("test", help="run JOCKY test files (.jky) that assert their own behaviour")
    p_test.add_argument("path", nargs="?", default="tests/lang",
                        help="file or directory (default: tests/lang)")
    p_test.add_argument("--pattern", default="*.jky", help="glob within the directory")
    p_test.add_argument("--wall-ms", type=float, default=30_000.0)
    p_test.add_argument("--sandbox", default="off", choices=["off", "vm", "ro", "strict"],
                        help="run every test under confinement")
    p_test.add_argument("--allow", default=None,
                        help="grant privileged capabilities to the tests (comma list)")
    p_test.add_argument("--json", action="store_true")
    p_test.add_argument("--verbose", action="store_true")
    p_test.set_defaults(func=cmd_test)

    p_ev = sub.add_parser("evidence", help="run the proof harness (polymorphism + repeatability + audit)",
        epilog="Examples:\n"
               "  jocky evidence --iterations 1000 --out evidence\n"
               "  jocky evidence --quick              # fast smoke run (10 iterations)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_ev.add_argument("--iterations", type=int, default=1000)
    p_ev.add_argument("--out", default="evidence")
    p_ev.add_argument("--quick", action="store_true")
    p_ev.set_defaults(func=cmd_evidence)

    p_attest = sub.add_parser("attest", help="hash-chain a case directory for tamper detection",
        epilog="Examples:\n"
               "  jocky attest ./case-2026-001\n"
               "  jocky attest ./case --note 'Initial collection' --anchor /mnt/usb/head.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p_attest.add_argument("directory")
    p_attest.add_argument("--note", default=None, help="free-text note stored in the manifest")
    p_attest.add_argument("--anchor", default=None,
                          help="also write the chain head here (keep it off-host)")
    p_attest.add_argument("--json", action="store_true")
    p_attest.set_defaults(func=cmd_attest)

    p_verify = sub.add_parser("verify", help="re-check a case directory against its manifest")
    p_verify.add_argument("directory")
    p_verify.add_argument("--key-file", default=None,
                          help="HMAC key (or set JOCKY_EVIDENCE_KEY) to also check the signature")
    p_verify.add_argument("--anchor", default=None, help="chain head stored outside the directory")
    p_verify.add_argument("--json", action="store_true")
    p_verify.set_defaults(func=cmd_verify)

    p_sign = sub.add_parser("sign", help="HMAC the chain head with an analyst key")
    p_sign.add_argument("directory")
    p_sign.add_argument("--key-file", default=None,
                        help="key file (or set JOCKY_EVIDENCE_KEY)")
    p_sign.add_argument("--json", action="store_true")
    p_sign.set_defaults(func=cmd_sign)

    p_serve = sub.add_parser("serve", help="run the central management server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8443)
    p_serve.add_argument("--token", default=None,
                         help="management token (or set JOCKY_TOKEN / --token-file)")
    p_serve.add_argument("--token-file", default=None,
                         help="file containing the token — preferred, because argv is "
                              "world-readable in /proc/<pid>/cmdline")
    p_serve.add_argument("--cert", default=None)
    p_serve.add_argument("--key", default=None)
    p_serve.add_argument("--state", default=".jocky-server")
    p_serve.set_defaults(func=cmd_serve)

    p_agent = sub.add_parser("agent", help="run a collection agent")
    p_agent.add_argument("--server", required=True)
    p_agent.add_argument("--token", default=None,
                         help="management token (or set JOCKY_TOKEN / --token-file)")
    p_agent.add_argument("--token-file", default=None, help="file containing the token")
    p_agent.add_argument("--interval", type=float, default=5.0)
    p_agent.add_argument("--once", action="store_true")
    p_agent.add_argument("--name", default=None)
    p_agent.add_argument("--state", default=".jocky-agent")
    p_agent.add_argument("--pin", default=None,
                         help="expected SHA-256 of the server certificate "
                              "(learned automatically at first enrolment)")
    p_agent.add_argument("--insecure", action="store_true",
                         help="do NOT verify or pin the server certificate — lab use only")
    p_agent.add_argument("--sni", default=None,
                         help="TLS SNI / Host header to present when the address in "
                              "--server differs (frontable deployments)")
    p_agent.add_argument("--verify-ca", action="store_true",
                         help="require a certificate valid against the system trust store "
                              "(default: self-signed server authenticated by --pin)")
    p_agent.set_defaults(func=cmd_agent)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # keep the CLI honest: print, never traceback
        print(f"jocky: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
