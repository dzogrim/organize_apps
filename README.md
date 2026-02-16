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
- `--include-hidden`: include hidden files/folders
- `--unknown-dir NAME`: fallback folder for unparsed entries (default `_Unsorted`)
- `--no-version-label LABEL`: for no-version names, use `App/LABEL/...` (default `unknown`)
- `--aliases-file /path/to/aliases.json`: additional canonical name mapping
- `--rebucket`: run bucket redistribution mode instead of organize mode

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
- Organize mode skips special unknown folder (`_Unsorted` by default).
- Rebucket mode skips entries already in their target bucket.
- Name collisions are handled with ` (2)`, ` (3)`, etc.
- If destination would be inside source, the tool repacks contents safely instead of failing.

## Name Normalization Rules

- Canonical key ignores case, spaces, punctuation.
- Common aliases are built-in (e.g. `LittleSnitch` -> `Little Snitch`).
- Edition suffixes are separated and kept in version folder:
  - `Pro`, `Plus Pro`, `X`
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
  "Syncover": "Syncovery",
  "Syncovey": "Syncovery",
  "iStatMenu Helper": "iStat Menus Helper"
}
```

## Practical Workflow

1. Run organize mode in dry-run.
2. Review planned moves.
3. Apply organize mode.
4. Run rebucket mode in dry-run.
5. Apply rebucket mode.
6. Re-run both modes to confirm `moved=0`.
