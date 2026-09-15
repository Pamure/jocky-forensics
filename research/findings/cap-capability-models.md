# Capability-based security: other runtimes vs JOCKY (`cap-capability-models`)

## Scope
JOCKY's authority model is `GUARDED_CAPABILITIES` (`jocky/rt/builtins.py:31-52`), `policy_ctx` (`jocky/runner.py:33-54`) and Landlock/seccomp (`jocky/sandbox.py`). Is deny-by-default aimed at the right things, and what is missing? Probes were read-only.

## How others do it
1. **WASI:** no ambient authority; each capability is a separate WIT import the host instantiates, "statically inspectable in the component binary itself"; filesystem is per-directory preopens, relative paths only. ⇒ JOCKY's grant surface is invisible until a native faults mid-run.
2. **Deno:** per-path `--allow-read=PATH`, per-host `--allow-net=host:port`, `--deny-*` overriding allow, and `DENO_AUDIT_PERMISSIONS` JSONL of `datetime|permission|value`; reading `/proc`, `/dev`, `/sys` needs its broadest grant (docs.deno.com, 2026-07-21). ⇒ JOCKY's read surface is Deno's most protected category, granted silently (`sandbox.py:75-77,265`) and unaudited.
3. **pledge/unveil:** the *program* declares promises, unlisted subsystems are removed, and violations kill with uncatchable `SIGABRT`; `unveil` adds per-path `r/w/c/x`, then locks ([pledge(2)](https://man.openbsd.org/pledge.2), OpenBSD-current 2026-09-10). ⇒ a declaration is a claim checked against the operator's grant, and refusal must not be catchable — today it is: **verified**, `try { mem.syscall(39) } catch e { set r = e }` finishes with `errors: []`, while `JockyLimitError` is uncatchable (`docs/DESIGN.md` §1.3).
4. **Starlark:** hermeticity (no I/O, no clock/random, bounded loops) makes evaluation a pure function of declared inputs ([design.md](https://github.com/bazelbuild/starlark/blob/master/design.md)). ⇒ unreachable for a collector; the bar is *declared* I/O plus flagging `now`/`sleep`/`sys.pid`.
5. **Layering:** Landlock is a stackable LSM whose layers only restrict and union, AppArmor staying the outer wall (kernel docs, Aug 2026). Rules grant beneath a path handle, so a subpath cannot be subtracted — Deno-style deny carve-outs are inexpressible.
6. **DFIR least authority:** SP 800-61r3 (Apr 2025) wants just-enough entitlements, minimal collection and auditability; Flatpak's precedent is static `finish-args`, just-in-time portal grants and `flatpak info --show-permissions`.

## Where JOCKY stands
| Capability | Has it? | Evidence · gap |
|---|---|---|
| Deny-by-default `mem.syscall`/`mem.memfd_run` | Yes | `builtins.py:31-33,393,395`, `runner.py:33-54`, `tests/test_security.py:32-56` · only two names exist (`runner.py:48-53`); refusals are catchable (below) |
| Deny-by-default files/env/net | No | `fs.read` opens any readable path (`builtins.py:323`); probe read `/etc/hostname` under default policy · reads *are* ambient |
| Per-path read grants | Partial | `sandbox.py:228-232,265-272` · additive to a fixed root set; scripts cannot narrow it |
| Per-native grants | No | `--allow` accepts only `syscall,exec` (`cli.py:340-341,375-376`) |
| Audit of granted capabilities | No | `RunResult` has none (`vm.py:132-139`); `--sandbox=vm --allow syscall --json` → `"checks": []`; only `JKY_ALLOW` (`fileless.py:198`) |
| Display before execution | No | no such subcommand (`cli.py:320-437`); refusal fires at call time, `try/catch` swallows it (verified) |

## Concrete improvements
1. **`needs` + `jocky capabilities <script|artifact>`** *(M; risk: namespace aliasing).* Implement as a `needs` keyword (`lang/lexer.py:22`), an `N.Needs` node plus dispatch (`lang/parser.py:121-142`), compiled to nothing. It resolves `Member(Ident(ns),name)`/`Index(Ident(ns),StrLit)` calls; natives are first-class (**verified**: `let f = fs.hash; f(p)` works), so an escaped namespace forces `natives:["*"]`, else certification is refused. The command prints declared/granted/effective, exiting non-zero when declared ⊄ granted.
```jocky
needs { natives: ["proc.list", "net.established", "det.triage"],
        read: ["/proc", "/sys", "/var/log"], write: [], priv: ["syscall"] }
```
2. **Policy object with deny precedence** *(M).* `Policy(natives, read, write, deny)` enforced in `_fn` (`builtins.py:38-52`), projected onto Landlock grants (`sandbox.py:265-272`); `deny` is wrapper-only. Defaults must reproduce today's behaviour.
3. **Uncatchable refusal** *(S).* Raise at VM level as `JockyLimitError` does; one finding per denial.
4. **Permission audit JSONL** *(M).* `--audit-permissions=FILE` in Deno's schema; grants and sandbox level into `RunResult`, hashed into `jocky attest`.
5. **Artifact manifest** *(M/L).* `needs` into the header (`encoder.py:540`); `exec` refuses when it exceeds the grant; advisory, not attested — the HMAC key ships inside (`lim-security` finding 7).

## Verification approach
- `jocky capabilities` over `scripts/*.jky`: plausible needs, exit 0; `priv:["syscall"]` without `--allow` refuses at `native_calls: 0`.
- `needs read:["/proc"]` + `--sandbox=ro`: `/proc/self/status` reads, a home-directory file returns `<unreadable: …>` — impossible today.
- After (3) the swallowing probe aborts; the deny-list blocks `/etc/shadow` but not `/etc/passwd`.
- Unchanged findings hashes at default policy; `test_security.py` and `test_sandbox.py` pass.

## Citations
- WASI *Security*, 2026-09-16 — https://wasi.dev/security
- Deno *Permissions*, 2026-07-21 — https://docs.deno.com/runtime/reference/permissions/
- Starlark design — https://github.com/bazelbuild/starlark/blob/master/design.md
- `pledge(2)`, OpenBSD-current 2026-09-10 — https://man.openbsd.org/pledge.2 ; `unveil(2)` — https://man.openbsd.org/unveil.2
- Landlock kernel docs, Aug 2026 — https://docs.kernel.org/userspace-api/landlock.html
- NIST SP 800-61r3, Apr 2025 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r3.pdf
- Flatpak *Sandbox Permissions*, 2026-09-16 — https://docs.flatpak.org/en/latest/sandbox-permissions.html
