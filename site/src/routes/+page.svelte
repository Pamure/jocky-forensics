<script>
	import versions from '$lib/versions.generated.js';

	const current = versions.find((entry) => entry.current) ?? versions[0];

	const install = `# Python 3.12+, Linux. No third-party dependencies.
git clone https://github.com/your-org/jocky.git && cd jocky
python3 -m venv venv && ./venv/bin/pip install -e .
./venv/bin/jocky doctor          # verify the host can run every mode`;

	const firstScript = `# triage.jky — reads /proc and /sys directly, spawns nothing
let report = det.triage()

emit {
  "host": report.host.hostname,
  "processes": report.scanned.processes,
  "sockets": report.scanned.sockets,
  "counts": report.counts
}

for finding in filter(report.findings, fn(f) {
  return f.severity == "high" or f.severity == "critical"
}) {
  emit {"check": f_check(finding), "title": finding.title}
}`;
</script>

<section class="hero">
	<span class="eyebrow">SIH26148 · NTRO · Blockchain &amp; Cybersecurity</span>
	<h1>A forensic scripting language built to work on systems that are watching.</h1>
	<p class="lede">
		JOCKY is a purpose-made language and runtime for computer and network forensic analysis:
		it collects from <code>/proc</code>, <code>/proc/net</code> and <code>/sys</code> without
		spawning a single external tool, compiles scripts into per-build unique artifacts, can run
		with nothing written to disk, and detects the very techniques it uses.
	</p>

	<div class="cta-row">
		<a class="cta primary" href="/docs/getting-started/installation">Install JOCKY</a>
		<a class="cta" href="/docs/getting-started/quickstart">Quickstart</a>
		<a class="cta" href="/docs/operations/evidence">Read the measurements</a>
	</div>

	<p class="pill" style="margin-top:1rem">documented version {current?.version ?? 'dev'} · Linux · stdlib only</p>
</section>

<div class="stat-strip">
	<div class="stat"><b>1000 / 1000</b><span>builds of one script produced unique SHA-256</span></div>
	<div class="stat"><b>0</b><span>child processes, execve and write-mode opens during collection</span></div>
	<div class="stat"><b>/memfd:python3</b><span>process image in fileless mode, nothing on disk</span></div>
	<div class="stat"><b>85</b><span>behavioural tests covering language, runtime, encoder, agent</span></div>
</div>

## Why a new language

<div class="grid-cards">
	<div class="card">
		<h3>Designed for evidence, not scripts</h3>
		<p>
			<code>emit</code> produces structured findings, the runtime turns host state into maps
			and lists you can filter and sort, and every native is namespaced
			(<code>proc</code>, <code>net</code>, <code>fs</code>, <code>sys</code>,
			<code>det</code>, <code>ioc</code>, <code>mem</code>).
		</p>
	</div>
	<div class="card">
		<h3>Quiet by construction</h3>
		<p>
			No <code>ps</code>, <code>ss</code>, <code>lsof</code>, <code>lsmod</code> or
			<code>find</code> is ever executed. A full triage reads kernel interfaces directly —
			measured with a Python audit hook over a real run.
		</p>
	</div>
	<div class="card">
		<h3>Unique bytes per deployment</h3>
		<p>
			Every build permutes opcodes, remaps local slots, encrypts and splits constants, inserts
			junk and re-keys the payload, so one script yields unlimited distinct artifacts with
			identical behaviour.
		</p>
	</div>
	<div class="card">
		<h3>Detection included</h3>
		<p>
			The runtime ships the mirror image of its own tradecraft: fileless processes, executable
			memfd mappings, deleted executables, hidden kernel modules, injected
			<code>LD_*</code>, hijackable <code>PATH</code> entries and IOC correlation.
		</p>
	</div>
</div>

## Install

```bash
{install}
```

## First script

```jocky
{firstScript}
```

Run it, then build a polymorphic artifact and execute it filelessly:

```bash
./venv/bin/jocky run scripts/triage.jky
./venv/bin/jocky build scripts/triage.jky -o /tmp/triage.jky.build
./venv/bin/jocky exec /tmp/triage.jky.build --json
./venv/bin/jocky fileless scripts/triage.jky      # exe -> /memfd:python3 (deleted)
```

## What we do not claim

<div class="grid-cards">
	<div class="card">
		<h3>No magic against kernel telemetry</h3>
		<p>
			eBPF/kprobe observers and auditd still see <code>memfd_create</code>,
			<code>execveat</code> and the file reads. JOCKY removes noisy-by-convention behaviour, not
			the observable syscalls beneath it.
		</p>
	</div>
	<div class="card">
		<h3>Running payloads stay visible</h3>
		<p>
			An in-memory process is visible in <code>/proc/&lt;pid&gt;/maps</code> while it runs —
			which is exactly why the detector that finds it ships in the same runtime.
		</p>
	</div>
	<div class="card">
		<h3>Linux-first</h3>
		<p>
			Collectors target procfs. The language, encoder and management protocol are portable;
			the Windows and macOS collectors are on the roadmap, not in the box.
		</p>
	</div>
	<div class="card">
		<h3>Domain fronting needs a CDN</h3>
		<p>
			The agent implements the client-side mechanic (separate SNI and Host). Without a real
			CDN in front, that is a hook — documented as such, never implied.
		</p>
	</div>
</div>
