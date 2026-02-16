#!/usr/bin/env python3
"""Organize macOS installers with deterministic, review-friendly conventions.

Primary mode:
- Parse application name/version/channel from heterogeneous file/folder names.
- Move entries into `App Name/Version/<original item>`.

Secondary mode (`--rebucket`):
- Re-distribute top-level entries into balanced Finder buckets
  (e.g. `A-B__checked`, `S__checked`).

Safety model:
- Dry-run by default.
- Idempotency-focused checks avoid repeated reshuffling on subsequent runs.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

KNOWN_EXTENSIONS = {
    ".iso",
    ".dmg",
    ".pkg",
    ".zip",
    ".tar",
    ".gz",
    ".xz",
    ".bz2",
    ".7z",
}

VERSION_RE = re.compile(
    r"""
    (?<![A-Za-z0-9])
    v?
    (
      \d+(?:[._\-\s]\d+){1,}
      (?:[-_.]?(?:b|beta|rc|alpha|ß)\d*)?
      |
      \d{1,5}(?:[-_.]?(?:b|beta|rc|alpha|ß)\d*)?
    )
    (?![A-Za-z0-9])
    """,
    re.IGNORECASE | re.VERBOSE,
)

TRAILING_TAG_RE = re.compile(
    r"(?:\s*[\[\(][^\]\)]+[\]\)]\s*|[-_ ]+(?:TNT|ATB|EDISO|MACKED|DOKDO|HCISO|CORE|DVT|LZ0|KG|INMAC|MAS))$",
    re.IGNORECASE,
)


@dataclass
class ParseResult:
    app_name: str
    version: str
    edition: str | None = None
    revision: str | None = None
    is_update: bool = False
    channel: str | None = None


BUILTIN_APP_ALIASES = {
    "signal": "Signal",
    "littlesnitch": "Little Snitch",
    "cleanmymacx": "CleanMyMac",
    "divxpro": "DivX",
    "divxpluspro": "DivX",
    "carboncopycloner": "Carbon Copy Cloner",
    "charlesproxy": "Charles",
    "crossftpproenterprise": "CrossFTP",
    "cisdemduplicatefinder": "Cisdem Duplicate Finder",
    "coconutbattery": "coconutBattery",
    "coconutbatteryplus": "coconutBattery",
    "copyless": "CopyLess",
    "diskdrillenterprise": "Disk Drill",
    "findanyfile": "Find Any File",
    "jamfproinstallerlinux": "Jamf Pro Installer for Linux",
    "scriptdebugger": "Script Debugger",
    "securityspy": "Security Spy",
    "signaldesktop": "Signal",
    "tableaudesktop": "Tableau Desktop",
    "textexpander": "TextExpander",
    "tinymediamanager": "tinyMediaManager",
    "unetbootin": "UNetbootin",
    "istatmenuhelper": "iStat Menus Helper",
    "syncover": "Syncovery",
    "syncovey": "Syncovery",
    "syncoverymac": "Syncovery",
    "drivegenius": "Drive Genius",
    "diskorder": "Disk Order",
    "jamfcaspersuite": "JAMF Casper Suite",
    "jamfcomposer": "JAMF Composer",
    "jamfpro": "Jamf Pro",
    "etrecheckpro": "EtreCheck Pro",
    "djvureader": "DjVu Reader",
    "djvureaderpro": "DjVu Reader",
    "dbeaverultimateedition": "DBeaver Ultimate Edition",
    "dbvisualizer": "DbVisualizer",
    "dbvisualizerpro": "DbVisualizer Pro",
    "dnscryptosx": "DNSCrypt OS X",
    "plisteditpro": "PlistEdit",
    "wifiexplorerpro": "WiFi Explorer",
}

REBUCKET_SCHEME: list[tuple[str, set[str]]] = [
    ("0-9", set("0123456789")),
    ("A-B", set("AB")),
    ("C-D", set("CD")),
    ("E-G", set("EFG")),
    ("H-I", set("HI")),
    ("J-L", set("JKL")),
    ("M", set("M")),
    ("N-P", set("NOP")),
    ("Q-R", set("QR")),
    ("S", set("S")),
    ("T-Z", set("TUVWXYZ")),
]

REBUCKET_DIR_RE = re.compile(r"^(?:0-9|[A-Z](?:-[A-Z])?)__checked$")


def normalize_spaces(value: str) -> str:
    """Collapse repeated whitespace and trim."""
    return re.sub(r"\s+", " ", value).strip()


def prettify_name(name: str) -> str:
    """Normalize separators in user-facing names."""
    cleaned = name.replace("_", " ")
    cleaned = re.sub(r"\s*-\s*", " ", cleaned)
    cleaned = normalize_spaces(cleaned)
    return cleaned


def normalize_version(raw: str) -> str:
    """Normalize extracted version tokens to dotted format."""
    version = raw.lower().replace("ß", "b").lstrip("v")
    version = re.sub(r"[\s_-]+", ".", version)
    return re.sub(r"\.+", ".", version).strip(".")


def normalize_edition(raw: str) -> str:
    """Normalize edition labels (`pro`, `x`) with title case."""
    words = [w.capitalize() for w in re.split(r"\s+", raw.strip()) if w]
    return " ".join(words)


UPDATE_MARKER_RE = re.compile(r"\b(?:upd|updt|update|updates)\b", re.IGNORECASE)


def detect_update_marker(raw_tail: str) -> bool:
    """Detect update markers only in text after version token."""
    # Only inspect text after the parsed version to avoid false positives
    # when "Update/Updater" is part of the product name itself.
    return UPDATE_MARKER_RE.search(raw_tail) is not None


def split_app_edition(raw_app: str) -> tuple[str, str | None]:
    """Split trailing edition suffix (`Pro`, `Plus Pro`, `X`) from app name."""
    patterns = [
        r"^(?P<base>.+?)\s+(?P<ed>Plus Pro)$",
        r"^(?P<base>.+?)\s+(?P<ed>Pro)$",
        r"^(?P<base>.+?)\s+(?P<ed>X)$",
    ]
    for pat in patterns:
        m = re.match(pat, raw_app, flags=re.IGNORECASE)
        if m:
            base = normalize_spaces(m.group("base"))
            edition = normalize_edition(m.group("ed"))
            if base:
                return base, edition
    return raw_app, None


def extract_channel(raw: str) -> str | None:
    """Extract release channel/group tag from bracket or tail markers."""
    channel = None

    bracket = re.findall(r"[\[(]([^\]\)]+)[\])]", raw)
    if bracket:
        channel = bracket[-1].strip()

    tail = re.search(r"(?:^|[-_\s])(TNT|ATB|EDISO|MACKED|DOKDO|HCISO|CORE|DVT|LZ0|KG|INMAC|MAS)$", raw, re.IGNORECASE)
    if tail:
        channel = tail.group(1)

    if channel:
        channel = re.sub(r"[^A-Za-z0-9.+-]", "", channel)

    return channel or None


def parse_name_and_version(entry_name: str) -> ParseResult | None:
    """Parse name/version metadata from one filesystem entry name.

    Returns:
    - `ParseResult` when a version token is found.
    - `None` when no version token can be identified.
    """
    base = entry_name
    suffix = Path(base).suffix.lower()
    if suffix in KNOWN_EXTENSIONS:
        base = base[: -len(suffix)]

    scan = base.replace("-", " ").replace("__", "_")
    normalized = prettify_name(base)
    matches = list(VERSION_RE.finditer(scan))
    if not matches:
        return None

    multipart = [m for m in matches if re.search(r"[._\-\s]", m.group(1))]
    version_match = multipart[0] if multipart else matches[0]
    version = normalize_version(version_match.group(1))
    revision: str | None = None
    if multipart:
        selected_idx = matches.index(version_match)
        for tail in matches[selected_idx + 1 :]:
            tail_raw = tail.group(0).strip()
            if re.fullmatch(r"v?\d+", tail_raw, flags=re.IGNORECASE):
                revision = normalize_version(tail.group(1))
                break

    raw_app = scan[: version_match.start()]
    raw_tail = scan[version_match.end() :]
    raw_app = TRAILING_TAG_RE.sub("", raw_app)
    raw_app = prettify_name(raw_app).strip("._- !")
    raw_app = normalize_spaces(raw_app)
    if not raw_app:
        return None

    app_name, edition = split_app_edition(raw_app)
    channel = extract_channel(normalized)
    is_update = detect_update_marker(raw_tail)

    return ParseResult(
        app_name=app_name,
        version=version,
        edition=edition,
        revision=revision,
        is_update=is_update,
        channel=channel,
    )


def parse_app_name_only(entry_name: str) -> str | None:
    """Best-effort extraction of app name for entries without version."""
    base = entry_name
    suffix = Path(base).suffix.lower()
    if suffix in KNOWN_EXTENSIONS:
        base = base[: -len(suffix)]

    cleaned = prettify_name(base).strip("._- !")
    cleaned = TRAILING_TAG_RE.sub("", cleaned).strip("._- !")
    cleaned = normalize_spaces(cleaned)
    if not cleaned:
        return None
    if not re.search(r"[A-Za-z]", cleaned):
        return None
    return cleaned


def safe_part(part: str) -> str:
    """Sanitize one path segment for conservative macOS-safe naming."""
    cleaned = re.sub(r"[/:]", "-", part).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:120] if cleaned else "Unknown"


def app_key(name: str) -> str:
    """Canonical key for grouping variants across punctuation/case changes."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def app_prettiness_score(name: str) -> tuple[int, int]:
    """Heuristic score used to keep the most readable display name."""
    has_space = 1 if " " in name.strip() else 0
    has_mixed_case = 1 if any(c.islower() for c in name) and any(c.isupper() for c in name) else 0
    return (has_space + has_mixed_case, len(name))


def choose_display_name(current: str | None, candidate: str, key: str, aliases: dict[str, str]) -> str:
    """Pick canonical display name using explicit aliases then readability."""
    if key in aliases and aliases[key]:
        return aliases[key]
    if current is None:
        return candidate
    return candidate if app_prettiness_score(candidate) > app_prettiness_score(current) else current


def load_aliases(path: Path | None) -> dict[str, str]:
    """Load alias mapping from JSON and merge with built-in aliases."""
    aliases: dict[str, str] = dict(BUILTIN_APP_ALIASES)
    if path is None:
        return aliases

    if not path.exists():
        print(f"WARN: aliases file not found: {path} (using built-in aliases only)")
        return aliases

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:
        print(f"WARN: failed to read aliases file {path}: {exc} (using built-in aliases only)")
        return aliases

    if not isinstance(raw, dict):
        print(f"WARN: aliases file {path} must be a JSON object; ignoring it")
        return aliases

    for src, dst in raw.items():
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        src_key = app_key(src)
        dst_name = prettify_name(dst).strip("._- ")
        if src_key and dst_name:
            aliases[src_key] = dst_name
    return aliases


def rebucket_label_for(name: str) -> str:
    """Map an entry name to its target rebucket label."""
    match = re.search(r"[A-Za-z0-9]", name)
    if not match:
        return "T-Z"
    ch = name[match.start()].upper()
    for label, charset in REBUCKET_SCHEME:
        if ch in charset:
            return label
    return "T-Z"


def iter_rebucket_sources(root: Path, include_hidden: bool) -> Iterable[Path]:
    """Yield entries to rebucket from root and legacy `*_checked` buckets."""
    for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not include_hidden and item.name.startswith("."):
            continue
        if item.name == Path(__file__).name:
            continue
        # If this is an existing bucket folder, rebucket its direct children.
        if item.is_dir() and REBUCKET_DIR_RE.match(item.name):
            for child in sorted(item.iterdir(), key=lambda p: p.name.lower()):
                if not include_hidden and child.name.startswith("."):
                    continue
                yield child
            continue
        yield item


def run_rebucket(root: Path, apply: bool, include_hidden: bool, unknown_dir: str) -> int:
    """Execute rebucket mode (dry-run by default)."""
    moved = 0
    skipped = 0
    destination_bucket_dirs = {f"{label}__checked" for label, _ in REBUCKET_SCHEME}

    for src in iter_rebucket_sources(root, include_hidden=include_hidden):
        if src.name == unknown_dir:
            print(f"SKIP: special folder {src}")
            skipped += 1
            continue

        # Keep canonical destination buckets at root in place.
        if src.parent == root and src.is_dir() and src.name in destination_bucket_dirs:
            print(f"SKIP: rebucket destination {src}")
            skipped += 1
            continue

        label = rebucket_label_for(src.name)
        target_dir = root / f"{label}__checked"
        if src.parent == target_dir:
            print(f"SKIP: already rebucketed {src}")
            skipped += 1
            continue

        move_entry(src, target_dir / src.name, apply)
        moved += 1

    mode = "APPLY" if apply else "DRY-RUN"
    print(f"\nSummary ({mode} REBUCKET): moved={moved}, skipped={skipped}, root={root}")
    return 0


def compute_destination(root: Path, src_name: str, app_display_name: str, parsed: ParseResult) -> Path:
    """Build destination path for one parsed entry."""
    app_part = safe_part(app_display_name)
    version_part = safe_part(parsed.version)
    if parsed.revision:
        version_part = f"{version_part} [v{safe_part(parsed.revision)}]"
    if parsed.edition:
        version_part = f"{version_part} [{safe_part(parsed.edition)}]"
    if parsed.is_update:
        version_part = f"{version_part} [Update]"
    if parsed.channel:
        version_part = f"{version_part} [{safe_part(parsed.channel)}]"
    return root / app_part / version_part / src_name


def iter_entries(root: Path, include_hidden: bool) -> Iterable[Path]:
    """Iterate top-level entries for organize mode."""
    for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not include_hidden and item.name.startswith("."):
            continue
        if item.name == Path(__file__).name:
            continue
        yield item


VERSION_DIR_RE = re.compile(r"^(?:unknown|\d+(?:\.\d+)*(?:\s+\[[^\]]+\])*)$", re.IGNORECASE)


def looks_like_app_container(path: Path) -> bool:
    """Heuristic: directory appears already organized by version."""
    if not path.is_dir():
        return False
    children = [c for c in path.iterdir() if not c.name.startswith(".")]
    if not children:
        return False
    # Idempotency-first heuristic:
    # if at least one version-like subdirectory exists, treat as organized container.
    return any(c.is_dir() and VERSION_DIR_RE.match(c.name) for c in children)


def already_grouped(root: Path, src: Path, app_display_name: str, parsed: ParseResult) -> bool:
    """Return True when entry already matches the expected app/version layout."""
    rel = src.relative_to(root)
    if len(rel.parts) < 3:
        return False
    app = safe_part(app_display_name)
    version = safe_part(parsed.version)
    if parsed.revision:
        version = f"{version} [v{safe_part(parsed.revision)}]"
    if parsed.edition:
        version = f"{version} [{safe_part(parsed.edition)}]"
    if parsed.is_update:
        version = f"{version} [Update]"
    current_app, current_version = rel.parts[0], rel.parts[1]
    return app_key(current_app) == app_key(app) and current_version.startswith(version)


def ensure_unique_destination(dest: Path) -> Path:
    """Resolve destination collisions by appending ` (n)` suffixes."""
    if not dest.exists():
        return dest

    base = dest.stem
    suffix = dest.suffix
    parent = dest.parent
    idx = 2
    while True:
        candidate = parent / f"{base} ({idx}){suffix}"
        if not candidate.exists():
            return candidate
        idx += 1


def move_entry(src: Path, dest: Path, apply: bool) -> None:
    """Print planned move and optionally execute it safely."""
    print(f"MOVE: {src} -> {dest}")
    if not apply:
        return

    # If destination is inside source directory, we cannot move src into itself.
    # Repack by moving children of src into the target directory.
    if src.is_dir():
        src_resolved = src.resolve()
        dest_resolved = (dest.parent.resolve() / dest.name)
        if dest_resolved.is_relative_to(src_resolved):
            target_dir = dest.parent
            print(f"REPACK: destination is inside source, moving contents into {target_dir}")
            target_dir.mkdir(parents=True, exist_ok=True)
            for child in src.iterdir():
                if child.name == target_dir.name:
                    continue
                child_dest = ensure_unique_destination(target_dir / child.name)
                shutil.move(str(child), str(child_dest))
            return

    dest.parent.mkdir(parents=True, exist_ok=True)
    final_dest = ensure_unique_destination(dest)
    shutil.move(str(src), str(final_dest))


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Organize installers into AppName/Version/<original-file-or-folder>.",
        epilog="Default behavior is dry-run. Use --apply to perform real moves.",
    )
    parser.add_argument("root", nargs="?", default=".", help="Directory to organize (default: current directory)")
    parser.add_argument("--apply", action="store_true", help="Actually move entries (default is dry-run)")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files and folders")
    parser.add_argument(
        "--rebucket",
        action="store_true",
        help="Re-distribute entries into balanced top-level buckets (A-B__checked, C-D__checked, ...)",
    )
    parser.add_argument("--unknown-dir", default="_Unsorted", help="Folder for entries where version parsing fails")
    parser.add_argument(
        "--no-version-label",
        default="unknown",
        help="Version label for app names without parsable version (set empty to keep them in unknown-dir)",
    )
    parser.add_argument(
        "--aliases-file",
        default=None,
        help="Path to JSON alias map, e.g. {'LittleSnitch': 'Little Snitch'}",
    )

    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()

    if not root.exists() or not root.is_dir():
        print(f"ERROR: not a directory: {root}", file=sys.stderr)
        return 2

    if args.rebucket:
        return run_rebucket(
            root=root,
            apply=args.apply,
            include_hidden=args.include_hidden,
            unknown_dir=args.unknown_dir,
        )

    aliases = load_aliases(Path(args.aliases_file).expanduser() if args.aliases_file else None)
    display_by_key: dict[str, str] = {}

    moved = 0
    skipped = 0
    unsorted = 0
    no_version = 0

    for src in iter_entries(root, include_hidden=args.include_hidden):
        if src.name == args.unknown_dir:
            print(f"SKIP: special folder {src}")
            skipped += 1
            continue
        if looks_like_app_container(src):
            print(f"SKIP: app container {src}")
            skipped += 1
            continue

        parsed = parse_name_and_version(src.name)

        if parsed is None:
            app_only = parse_app_name_only(src.name)
            if app_only and args.no_version_label:
                parsed = ParseResult(app_name=app_only, version=args.no_version_label)
                no_version += 1
            else:
                destination = root / args.unknown_dir / src.name
                move_entry(src, destination, args.apply)
                unsorted += 1
                moved += 1
                continue

        key = app_key(parsed.app_name)
        display_by_key[key] = choose_display_name(display_by_key.get(key), parsed.app_name, key, aliases)
        app_display_name = display_by_key[key]

        if already_grouped(root, src, app_display_name, parsed):
            print(f"SKIP: already grouped {src}")
            skipped += 1
            continue

        destination = compute_destination(root, src.name, app_display_name, parsed)
        move_entry(src, destination, args.apply)
        moved += 1

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(
        f"\nSummary ({mode}): moved={moved}, skipped={skipped}, "
        f"unsorted={unsorted}, no_version={no_version}, root={root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
