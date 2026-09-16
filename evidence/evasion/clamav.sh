#!/bin/bash
# ClamAV as a second engine for the evasion evaluation — installed without root.
#
# Why this exists: `docs/EVASION.md` reported one vendor (Defender), and one
# engine is one data point. "Comparative evasion evaluation" is deliverable 5.
# Installing ClamAV normally needs `sudo apt install` plus ~1 GB; this obtains
# the same engine for a normal account by extracting the .debs and running from
# a private mount namespace.
#
# What it does NOT do: modify /etc, install anything system-wide, or need root.
# Every step lands in a scratch directory. The namespace is a *private* mount
# namespace (unshare -m), so the bind mount over /etc exists only inside it.
#
# Usage:
#   EVIDENCE_DIR=/path/to/artifacts ./clamav.sh
#
# Exit: 0 if every scanned file is clean, 1 if anything is detected, 2 on setup
# failure. A positive control (EICAR) runs first and MUST be detected — without
# it, "0 infected" would be indistinguishable from a broken install.

set -u

WORK="${CLAMAV_WORK:-/tmp/jky-clamav}"
TARGETS="${EVIDENCE_DIR:-}"
STEPS_OK=0

log() { printf '  %s\n' "$*"; }

if [ -z "$TARGETS" ]; then
    echo "usage: EVIDENCE_DIR=<dir to scan> $0" >&2
    exit 2
fi

echo "== 1. obtain the engine (no root) =="
mkdir -p "$WORK/debs" && cd "$WORK/debs" || exit 2
# Download each package individually: one failure must not silently sink the
# rest, and the set must be complete before anything is run.
for pkg in clamav libclamav12 clamav-freshclam libmspack0t64; do
    if ls ./"${pkg}"*.deb >/dev/null 2>&1; then continue; fi
    apt-get download "$pkg" >/dev/null 2>&1 || \
        echo "  note: $pkg is unavailable from the configured archive"
done
# libmspack0t64 is the 24.04 name (the time_t transition renamed it); fall back
# to the older name so this works on 22.04 as well.
if ! ls ./libmspack*.deb >/dev/null 2>&1; then
    apt-get download libmspack0 >/dev/null 2>&1 || \
        echo "  note: no libmspack package resolved"
fi
if ! ls ./*.deb >/dev/null 2>&1; then
    echo "  could not download the packages (no network or no apt cache)" >&2
    exit 2
fi
cd "$WORK" || exit 2
mkdir -p extracted
for deb in debs/*.deb; do dpkg-deb -x "$deb" extracted 2>/dev/null; done
log "extracted $(ls debs/*.deb | wc -l) package(s)"

LIB="$WORK/extracted/usr/lib/x86_64-linux-gnu"
export LD_LIBRARY_PATH="$LIB"
MISSING=$(ldd "$WORK/extracted/usr/bin/clamscan" 2>/dev/null | grep -c "not found")
if [ "$MISSING" -ne 0 ]; then
    echo "  $MISSING shared libraries are still missing:" >&2
    ldd "$WORK/extracted/usr/bin/clamscan" | grep "not found" >&2
    exit 2
fi
log "engine: $("$WORK/extracted/usr/bin/clamscan" --version 2>/dev/null | head -1)"

echo "== 2. signatures =="
if [ ! -s "$WORK/db/main.cvd" ]; then
    mkdir -p "$WORK/db"
    # Heredoc is unquoted so $WORK expands, which means shell metacharacters in
    # the comments would execute: backticks around an option name are command
    # substitution in that context, so the comments use plain quoting.
    cat > "$WORK/freshclam.conf" <<EOF
DatabaseDirectory $WORK/db
CVDCertsDirectory $WORK/extracted/etc/clamav/certs
DatabaseMirror database.clamav.net
DatabaseOwner $(id -un)
# Signature verification normally needs /etc/clamav/certs, which only root can
# create. CVDCertsDirectory above satisfies initialisation, because the package
# ships its own CA under usr/share; the database *test* spawns a child that
# resolves the path from the compiled-in default instead of the config, so the
# test is disabled here and clamscan does the verification later against the
# same CA presented through the private mount namespace.
TestDatabases no
EOF
    if [ ! -x "$WORK/extracted/usr/bin/freshclam" ]; then
        echo "  freshclam is missing from the extracted packages" >&2
        exit 2
    fi
    "$WORK/extracted/usr/bin/freshclam" \
        --config-file="$WORK/freshclam.conf" --stdout 2>&1 | tail -3
fi
if [ ! -s "$WORK/db/main.cvd" ] || [ ! -s "$WORK/db/daily.cvd" ]; then
    echo "  signature database is incomplete; cannot scan" >&2
    exit 2
fi
log "daily.cvd $(du -h "$WORK/db/daily.cvd" | cut -f1), main.cvd $(du -h "$WORK/db/main.cvd" | cut -f1)"

echo "== 3. namespace runner =="
# clamscan's signature verifier hardcodes /etc/clamav/certs. A private mount
# namespace can present that path without touching the host: unshare -r maps
# this uid to root inside the namespace, and the bind mount is namespace-local.
ETC_COPY="$WORK/etc-copy"
if [ ! -d "$ETC_COPY" ]; then
    cp -a /etc "$ETC_COPY" 2>/dev/null
    mkdir -p "$ETC_COPY/clamav/certs"
    cp "$WORK/extracted/etc/clamav/certs/clamav.crt" "$ETC_COPY/clamav/certs/" 2>/dev/null
fi
cat > "$WORK/clamscan.sh" <<EOF
#!/bin/bash
mount --bind $ETC_COPY /etc
export LD_LIBRARY_PATH=$LIB
exec $WORK/extracted/usr/bin/clamscan --database=$WORK/db "\$@"
EOF
chmod +x "$WORK/clamscan.sh"
if ! unshare -r -m true 2>/dev/null; then
    echo "  unprivileged namespaces are unavailable on this host" >&2
    exit 2
fi
log "private mount namespace available"

echo "== 4. POSITIVE CONTROL (EICAR) =="
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$WORK/eicar.com"
CONTROL=$(unshare -r -m "$WORK/clamscan.sh" --infected "$WORK/eicar.com" 2>/dev/null)
if ! printf '%s' "$CONTROL" | grep -q "FOUND"; then
    echo "  CONTROL FAILED — the engine did not detect EICAR, so results below" >&2
    echo "  would be meaningless. Output was:" >&2
    printf '%s\n' "$CONTROL" >&2
    exit 2
fi
log "$(printf '%s' "$CONTROL" | grep FOUND | head -1)"

echo "== 5. scan =="
RESULT=$(unshare -r -m "$WORK/clamscan.sh" --infected "$TARGETS" 2>/dev/null)
printf '%s\n' "$RESULT" | grep -E "FOUND|Infected files|Scanned files" || true
DETECTED=$(printf '%s' "$RESULT" | grep -c "FOUND")
INFECTED=$(printf '%s' "$RESULT" | sed -n 's/^Infected files: \([0-9]*\)/\1/p')
log "detections: ${INFECTED:-unknown}"

if [ "${DETECTED:-0}" -gt 0 ]; then
    exit 1
fi
STEPS_OK=1
[ "$STEPS_OK" -eq 1 ] && echo "== ClamAV: no detection, control passed =="
exit 0
