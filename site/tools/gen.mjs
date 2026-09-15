/**
 * Documentation generator wrapper.
 *
 * The real generators are Python (`tools/gen_reference.py` reads the source
 * tree, `tools/gen_versions.py` reads git). Hosted builders — notably Vercel's —
 * may not provide a Python interpreter, and the generated pages are committed
 * anyway, so a missing interpreter is a warning, never a failed build.
 */
import { spawnSync } from 'node:child_process';

const steps = [
	['tools/gen_versions.py', 'version metadata'],
	['tools/gen_reference.py', 'reference pages']
];

const python = process.env.PYTHON || 'python3';
let generated = 0;

for (const [script, what] of steps) {
	const result = spawnSync(python, [script], { stdio: 'inherit' });
	if (result.error || result.status !== 0) {
		console.warn(
			`gen: skipped ${what} (${python} ${script} failed) — using the committed output`
		);
		continue;
	}
	generated += 1;
}

console.log(`gen: ${generated}/${steps.length} generator(s) ran`);
process.exit(0);
