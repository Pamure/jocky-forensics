/**
 * Minimal, dependency-free syntax highlighter.
 *
 * Rationale: the docs site must render code blocks for JOCKY, Python, bash and
 * JSON without pulling a highlighter (and its theme) into the build.  A small
 * ordered rule table per language is enough for documentation snippets, stays
 * readable, and keeps highlighting identical between `vite build` and any
 * offline copy of the site.
 *
 * Output is HTML-escaped throughout; only the wrapper spans are emitted by us,
 * so there is no injection path from code samples.
 */

const KEYWORDS = {
	jocky: [
		'let', 'set', 'if', 'elif', 'else', 'while', 'for', 'in', 'fn', 'return',
		'break', 'continue', 'emit', 'try', 'catch', 'and', 'or', 'not',
		'true', 'false', 'nil'
	],
	python: [
		'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue',
		'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global',
		'if', 'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass',
		'raise', 'return', 'try', 'while', 'with', 'yield', 'True', 'False', 'None',
		'self', 'match', 'case'
	],
	bash: [
		'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'do', 'done', 'case',
		'esac', 'function', 'return', 'export', 'local', 'echo', 'cd', 'set',
		'sudo', 'curl', 'wget', 'grep', 'sed', 'awk', 'cat', 'chmod', 'mkdir',
		'rm', 'git', 'npm', 'python3', 'pip', 'docker', 'vercel', 'tar', 'kill'
	]
};

const BUILTINS = {
	jocky: [
		'print', 'len', 'str', 'int', 'float', 'type', 'range', 'transform',
		'filter', 'sort', 'sort_by', 'count', 'join', 'keys', 'values', 'contains',
		'dict', 'now', 'sleep', 'json_encode', 'json_decode', 'hex', 'error'
	],
	python: [
		'print', 'len', 'range', 'str', 'int', 'float', 'dict', 'list', 'set',
		'tuple', 'open', 'enumerate', 'sorted', 'zip', 'isinstance', 'getattr',
		'hasattr', 'super', 'type', 'repr', 'format', 'any', 'all'
	]
};

const NAMESPACES = ['proc', 'net', 'fs', 'sys', 'det', 'ioc', 'mem'];

const LANG_ALIASES = {
	jky: 'jocky',
	jocky: 'jocky',
	py: 'python',
	python: 'python',
	sh: 'bash',
	shell: 'bash',
	bash: 'bash',
	console: 'bash',
	json: 'json',
	jsonc: 'json',
	text: 'text',
	'': 'text'
};

function escapeHtml(text) {
	return text
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
}

function span(kind, text) {
	return `<span class="tok-${kind}">${escapeHtml(text)}</span>`;
}

/** Ordered rules; the first match at the current offset wins. */
function rulesFor(language) {
	const keywords = KEYWORDS[language] || [];
	const builtins = BUILTINS[language] || [];
	const wordBoundary = (words) => new RegExp(`^(?:${words.join('|')})\\b`);
	const rules = [];

	if (language === 'json') {
		rules.push([/^"(?:[^"\\]|\\.)*"(?=\s*:)/, (m) => span('property', m)]);
		rules.push([/^"(?:[^"\\]|\\.)*"/, (m) => span('string', m)]);
		rules.push([/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/, (m) => span('number', m)]);
		rules.push([/^(?:true|false|null)\b/, (m) => span('keyword', m)]);
		return rules;
	}

	// comments and strings first so they win over keywords inside them
	if (language === 'bash') {
		rules.push([/^#[^\n]*/, (m) => span('comment', m)]);
		rules.push([/^'[^']*'/, (m) => span('string', m)]);
		rules.push([/^"(?:[^"\\]|\\.)*"/, (m) => span('string', m)]);
	} else {
		rules.push([/^#[^\n]*/, (m) => span('comment', m)]);
		rules.push([/^"""[\s\S]*?"""/, (m) => span('string', m)]);
		rules.push([/^"(?:[^"\\]|\\.)*"/, (m) => span('string', m)]);
		rules.push([/^'(?:[^'\\]|\\.)*'/, (m) => span('string', m)]);
	}

	if (language === 'bash') {
		rules.push([/^\$\{[^}]*\}|^\$[A-Za-z_][A-Za-z0-9_]*/, (m) => span('property', m)]);
		rules.push([/^(?:--?[A-Za-z][\w-]*)/, (m) => span('property', m)]);
	}

	if (keywords.length) {
		rules.push([wordBoundary(keywords), (m) => span('keyword', m)]);
	}
	if (language === 'jocky') {
		rules.push([
			new RegExp(`^(?:${NAMESPACES.join('|')})\\b`),
			(m) => span('builtin', m)
		]);
	}
	if (builtins.length) {
		rules.push([
			new RegExp(`^(?:${builtins.join('|')})\\b(?=\\s*\\()?`),
			(m) => span('func', m)
		]);
	}

	if (language !== 'bash') {
		rules.push([/^\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/, (m) => span('number', m)]);
	} else {
		rules.push([/^\b\d+\b/, (m) => span('number', m)]);
	}

	rules.push([/^[A-Za-z_][A-Za-z0-9_]*(?=\s*\()/, (m) => span('func', m)]);
	rules.push([/^[A-Za-z_][A-Za-z0-9_]*(?=\s*[:=])/, (m) => span('property', m)]);
	rules.push([/^[{}()[\];:,.]/, (m) => span('punct', m)]);
	return rules;
}

/**
 * Highlight `code` for `language`, returning escaped HTML with token spans.
 */
export function highlight(code, language = 'text') {
	const source = String(code ?? '').replace(/\n$/, '');
	const lang = LANG_ALIASES[String(language || '').toLowerCase()] || 'text';
	const rules = rulesFor(lang);
	if (!rules.length) return escapeHtml(source);

	let out = '';
	let index = 0;
	while (index < source.length) {
		const rest = source.slice(index);
		let matched = false;
		for (const [pattern, render] of rules) {
			const match = pattern.exec(rest);
			if (match && match[0].length) {
				out += render(match[0]);
				index += match[0].length;
				matched = true;
				break;
			}
		}
		if (!matched) {
			// accumulate plain text until the next rule could match
			let next = index + 1;
			while (next < source.length) {
				const probe = source.slice(next);
				if (rules.some(([pattern]) => pattern.test(probe))) break;
				next += 1;
			}
			out += escapeHtml(source.slice(index, next));
			index = next;
		}
	}
	return out;
}

/** Languages advertised in the docs navigation/legend. */
export const SUPPORTED_LANGUAGES = ['jocky', 'python', 'bash', 'json'];
