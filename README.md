# macOS Installers Organizer

Script:
`organize_apps.py`

This tool has two modes:

1. Organize installers into `App Name/Version/<original file or folder>`.
2. Rebucket entries into balanced Finder buckets (`A-B__checked`, `S__checked`, ...).

Default behavior is always `dry-run`.

## Quickstart

Preview organize mode:

```bash
python3 ./organize_apps.py "/path/to/installers"
```

Apply organize mode:

```bash
python3 ./organize_apps.py "/path/to/installers" --apply
```

Preview rebucket mode:

```bash
python3 ./organize_apps.py "/path/to/root" --rebucket
```

Apply rebucket mode:

```bash
python3 ./organize_apps.py "/path/to/root" --rebucket --apply
```

## CLI Options

- `--apply`: perform moves (without this flag, only planned moves are printed)
- `--verbose`: show `SKIP:` diagnostics (hidden by default)
- `--include-hidden`: include hidden files/folders
- `--unknown-dir NAME`: fallback folder for unparsed entries (default `_Unsorted`)
- `--no-version-label LABEL`: for no-version names, use `App/LABEL/...` (default `unknown`)
- `--aliases-file /path/to/aliases.json`: additional canonical name mapping
- `--rebucket`: run bucket redistribution mode instead of organize mode
- `--normalize-editions`: split edition suffixes into version tags (`Enterprise`, `Plus`, `Professional`, etc.)
- `--normalize-publishers`: extract publisher from app name (`Roxio Toast ...` -> app `Toast ...` + `[Publisher:Roxio]`)
- `--publishers-file /path/to/publishers.json`: optional publisher aliases (JSON array or object)
- `--refine-containers`: inspect already organized app folders and flatten one redundant nested wrapper level
- `--promote-unknown`: promote parseable entries found under `unknown/` tracks in already grouped app containers
- `--audit`: generate a non-destructive maintenance report (unknown dirs, wrapper candidates, sidecars, empty dirs)

## Refine Containers Mode

`--refine-containers` is an opt-in cleanup pass for app folders that were already grouped before.

What it does:
- Flattens one redundant wrapper level in version tracks.
- Example:
  - `Microsoft Office/2019/2019.16.32/Microsoft Office 2019 16.32/<files>`
  - becomes `Microsoft Office/2019/2019.16.32/<files>`

What it does not do:
- It does not recurse indefinitely; only one safe wrapper level is flattened.
- It does not remove folders automatically (empty wrappers may remain).
- It does not perform moves unless `--apply` is provided.

## Promote Unknown Mode

`--promote-unknown` is an opt-in cleanup pass for legacy `unknown` tracks inside existing app containers.

What it does:
- Finds parseable entries directly under `unknown/` (or your custom `--unknown-dir`) within grouped app folders.
- Promotes them to `AppName/Version/<original item>` under that same app container.

Example:
- `Micromat/unknown/TechTool Protogo 4.0.5/...`
- becomes `Micromat/unknown/TechTool Protogo/4.0.5/TechTool Protogo 4.0.5/...`

It is dry-run by default; add `--apply` to perform moves.

## Audit Mode

`--audit` runs a read-only quality scan and prints maintenance metrics, including:
- `unknown_dirs`
- `parseable_in_unknown`
- `wrapper_candidates`
- `sidecars`
- `empty_dirs`
- sample paths for each category

Example:

```bash
python3 ./organize_apps.py "/path/to/root" --audit
```

Recommended usage:

```bash
python3 ./organize_apps.py "/path/to/root" \
  --refine-containers \
  --normalize-editions \
  --normalize-publishers \
  --publishers-file ./publishers.json
```

Then apply:

```bash
python3 ./organize_apps.py "/path/to/root" \
  --refine-containers \
  --normalize-editions \
  --normalize-publishers \
  --publishers-file ./publishers.json \
  --apply
```

Summary line includes:
- `promoted_unknown=A/B`
  - `A`: unknown entries promoted
  - `B`: parseable unknown entries inspected
- `refined=X/Y`
- `X`: refinements planned/performed
- `Y`: candidate structures inspected

## Rebucket Optimal Scheme

- `0-9__checked`
- `A-B__checked`
- `C-D__checked`
- `E-G__checked`
- `H-I__checked`
- `J-L__checked`
- `M__checked`
- `N-P__checked`
- `Q-R__checked`
- `S__checked`
- `T-Z__checked`

## Idempotency Guarantees

- Organize mode skips already organized app containers.
- With `--refine-containers`, app containers are inspected but only a safe one-level flatten is attempted.
- Organize mode skips special unknown folder (`_Unsorted` by default).
- Rebucket mode skips entries already in their target bucket.
- Name collisions are handled with ` (2)`, ` (3)`, etc.
- If destination would be inside source, the tool repacks contents safely instead of failing.

## Name Normalization Rules

- Canonical key ignores case, spaces, punctuation.
- Common aliases are built-in (e.g. `LittleSnitch` -> `Little Snitch`).
- Edition suffixes are separated and kept in version folder:
  - `Pro`, `Plus Pro`, `Enterprise`, `Professional`, `Business Edition`, `Suite`, `X`, etc. (with `--normalize-editions`)
- Publisher can be separated and kept in version folder:
  - `Roxio Toast Titanium Pro` -> app `Toast Titanium`, version `unknown [Pro] [Publisher:Roxio]` (with `--normalize-publishers`)
- Update markers after version are tagged:
  - `Upd`, `Updt`, `Update` -> `[Update]`
- Revision marker after version is preserved:
  - `2016.10 v2` -> `2016.10 [v2]`
- Channel/release tags are preserved in version folder:
  - e.g. `[TNT]`, `[atb]`, `[HCISO]`

## Alias File Format

Example `aliases.json`:

```json
{
  "LittleSnitch": "Little Snitch",
  "Hands Off!": "Hands Off",
  "Syncover": "Syncovery",
  "Syncovey": "Syncovery",
  "iStatMenu Helper": "iStat Menus Helper"
}
```

Example `publishers.json`:

```json
{
  "Roxio": "Roxio",
  "Microsoft Corporation": "Microsoft",
  "Adobe Inc.": "Adobe"
}
```

## Practical Workflow

1. Run organize mode in dry-run.
2. Review planned moves.
3. Apply organize mode.
4. Run rebucket mode in dry-run.
5. Apply rebucket mode.
6. Re-run both modes to confirm `moved=0`.
