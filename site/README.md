# JOCKY documentation site

Two build paths exist on purpose. The SvelteKit one is the primary site; the
Python one is the guarantee.

| Path | Command | Requires | Output |
|---|---|---|---|
| SvelteKit (primary) | `npm ci && npm run build` | Node 20+, network for the first install | `build/` |
| Static fallback | `python3 tools/build_static.py` | Python 3.12 only | `dist/` |

Both render the same `content/**/*.md` files, the same navigation manifest
(`nav.json`) and the same stylesheet (`src/app.css`), so the two outputs are
visually equivalent. The fallback exists because documentation that cannot be
built offline, on an air-gapped reviewer's laptop, is not documentation you can
rely on.

## Development

```bash
npm install
npm run dev          # http://localhost:5174, regenerates the reference pages first
npm run build        # prerender everything into build/
npm run preview      # serve the built site
```

The generated pages (`content/language/standard-library.md`,
`content/runtime/api.md`, `content/runtime/detection.md`,
`content/operations/cli.md`, `content/project/releases.md`) are produced by
`tools/gen_reference.py` and `tools/gen_versions.py`. Never edit them by hand —
edit the source they read (`jocky/rt/builtins.py`, `jocky/rt/detect.py`,
`jocky/cli.py`, git tags) and re-run `npm run gen`.

## Content rules

1. Every command shown in a page must have been run, and the output pasted
   verbatim. No invented flags, numbers or file paths.
2. Numbers come from `evidence/report.md` or from a command that produced them.
3. Anything the tool cannot do is stated as such; the project's credibility
   rests on the difference between measured claims and marketing.
4. `nav.json` is the single source of navigation. The SvelteKit build *fails*
   when a listed page is missing; the static builder warns. Both are
   deliberate: a dead link is a documentation bug.

## Publishing

```bash
# 1. one-off: authenticate (interactive) or export a token
npx vercel login
#    or: export VERCEL_TOKEN=…   (https://vercel.com/account/tokens)

# 2. preview deployment
npx vercel deploy --yes

# 3. production deployment
npx vercel deploy --prod --yes

# with a token (CI / non-interactive)
npx vercel deploy --prod --yes --token "$VERCEL_TOKEN"
```

Before deploying a new release, refresh any page that quotes version-specific
output (`jocky --version`, `doctor` transcripts, build metadata). The version
banner and `project/releases` regenerate themselves from `git tag`; prose does
not. Where a quote is illustrative, label it as "at the time of writing" so a
later bump does not turn the page into a false statement.

`vercel.json` pins the contract: `npm run build`, output directory `build/`,
`cleanUrls` on, long-lived caching for hashed assets. The repository root is
*not* the project root — deploy from `site/`, or point Vercel at it as the Root
Directory.
