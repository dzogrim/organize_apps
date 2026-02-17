#!/usr/bin/env python3
"""Organize macOS installers with deterministic, review-friendly conventions.

Core goals:
- Normalize inconsistent release names into stable app/version paths.
- Keep operations auditable (explicit MOVE lines, concise summaries).
- Prefer idempotent behavior so repeated runs do not churn the tree.

Main modes:
- Default organize mode: parse and move into `App/Version/<original-item>`.
- `--rebucket`: rebalance top-level entries into fixed `*_checked` buckets.
- `--promote-unknown`: parse and promote entries found under unknown tracks.
- `--refine-containers`: flatten one redundant wrapper level in app containers.
- `--audit`: read-only quality report for maintenance planning.

Safety model:
- Dry-run by default (`--apply` required for writes).
- Collision-safe moves (`(2)`, `(3)`, ...).
- Conservative skips for already-organized containers and bucket roots.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from collections import Counter
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
      \d{1,3}u\d{1,4}(?:[._\-]\d+)?
      |
      \d{8}(?:[._\-]\d{4,8})?
      |
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
    """Structured parse output used to compute deterministic destinations."""
    app_name: str
    version: str
    edition: str | None = None
    publisher: str | None = None
    revision: str | None = None
    is_update: bool = False
    channel: str | None = None
    normalization_confidence: str | None = None
    normalization_notes: list[str] | None = None


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
    "roxiotoasttitanium": "Toast Titanium",
    "toasttitaniumpro": "Toast Titanium",
    "additionaltoolsforxcode": "Additional Tools for Xcode",
    "devicesupportformacos": "Device Support for macOS",
    "graphicstoolsforxcode": "Graphics Tools for Xcode",
    "hardwareiotoolsforxcode": "Hardware IO Tools for Xcode",
    "kerneldebugkit": "Kernel Debug Kit",
    "sfsymbols": "SF Symbols",
    "fonttoolsforxcode": "Font Tools for Xcode",
    "elstensoftwarebliss": "Bliss",
    "elstensoftwareblissv": "Bliss",
    "xcode": "Xcode",
    "xode": "Xcode",
    "jdk": "JDK - Java Development Kit",
    "javajdk": "JDK - Java Development Kit",
    "javadevelopmentkit": "JDK - Java Development Kit",
    "javasedevelopmentkit": "JDK - Java Development Kit",
    "jre": "JRE - Java Runtime Environment",
    "javajre": "JRE - Java Runtime Environment",
    "javaruntimeenvironment": "JRE - Java Runtime Environment",
    "javaseruntimeenvironment": "JRE - Java Runtime Environment",
    "javaseruntimeenv": "JRE - Java Runtime Environment",
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
VERSIONISH_DIR_RE = re.compile(r"^(?:\d+(?:[.\s]\d+)+|\d{4})\s*$")
SIDECAR_RE = re.compile(r"(?i)(keygen|crack|serial|license|\.nfo$|\.rtf$|\bkg\b|\bsn\b)")


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
    version = re.sub(r"\.+", ".", version).strip(".")

    # Date-like version: YYYYMMDD(.build) -> YYYY.MM.DD(.build)
    m = re.fullmatch(r"(?P<date>\d{8})(?:\.(?P<build>\d{4,8}))?", version)
    if m:
        y = int(m.group("date")[0:4])
        mo = int(m.group("date")[4:6])
        d = int(m.group("date")[6:8])
        if 1970 <= y <= 2099 and 1 <= mo <= 12 and 1 <= d <= 31:
            base = f"{y:04d}.{mo:02d}.{d:02d}"
            build = m.group("build")
            return f"{base}.{build}" if build else base

    return version


def normalize_edition(raw: str) -> str:
    """Normalize edition labels (`pro`, `x`) with title case."""
    words = [w.capitalize() for w in re.split(r"\s+", raw.strip()) if w]
    return " ".join(words)


UPDATE_MARKER_RE = re.compile(r"\b(?:upd|updt|update|updates)\b", re.IGNORECASE)

EDITION_TOKENS: tuple[tuple[str, ...], ...] = (
    ("plus", "pro"),
    ("business", "edition"),
    ("ultimate", "edition"),
    ("professional",),
    ("enterprise",),
    ("business",),
    ("corporate",),
    ("premium",),
    ("ultimate",),
    ("community",),
    ("standard",),
    ("express",),
    ("lite",),
    ("suite",),
    ("plus",),
    ("pro",),
    ("x",),
)

# Cases where suffix-like tokens are part of the product name itself.
EDITION_PROTECTED_KEYS = {
    "tableplus",
    "photoplus",
    "sqlpro",
    "gpgsuite",
    "murusprosuite",
}

BUILTIN_PUBLISHER_ALIASES = {
    "roxio": "Roxio",
}

# Optional parent grouping for selected products.
APP_PARENT_GROUPS = {
    "xcode": "Apple Developer Tools",
    "additionaltoolsforxcode": "Apple Developer Tools",
    "devicesupportformacos": "Apple Developer Tools",
    "graphicstoolsforxcode": "Apple Developer Tools",
    "hardwareiotoolsforxcode": "Apple Developer Tools",
    "kerneldebugkit": "Apple Developer Tools",
    "sfsymbols": "Apple Developer Tools",
    "fonttoolsforxcode": "Apple Developer Tools",
    "jdkjavadevelopmentkit": "Java",
    "jrejavaruntimeenvironment": "Java",
}


def detect_update_marker(raw_tail: str) -> bool:
    """Detect update markers only in text after version token."""
    # Only inspect text after the parsed version to avoid false positives
    # when "Update/Updater" is part of the product name itself.
    return UPDATE_MARKER_RE.search(raw_tail) is not None


def split_app_edition(raw_app: str, enabled: bool) -> tuple[str, str | None, str | None, str | None]:
    """Split known trailing edition suffixes from app name when enabled."""
    if not enabled:
        return raw_app, None, None, None

    words = [w for w in re.split(r"\s+", raw_app.strip()) if w]
    if len(words) < 2:
        return raw_app, None, None, None

    key = app_key(raw_app)
    if key in EDITION_PROTECTED_KEYS:
        return raw_app, None, None, None

    lowered = [w.lower() for w in words]
    for token_seq in EDITION_TOKENS:
        n = len(token_seq)
        if n >= len(words):
            continue
        if tuple(lowered[-n:]) != token_seq:
            continue
        base = normalize_spaces(" ".join(words[:-n]))
        edition = normalize_edition(" ".join(words[-n:]))
        if not base:
            continue
        confidence = "high" if n > 1 else "medium"
        note = f"edition:{edition}"
        return base, edition, confidence, note

    return raw_app, None, None, None


def split_publisher(raw_app: str, enabled: bool, publishers: dict[str, str]) -> tuple[str, str | None, str | None, str | None]:
    """Extract publisher from name prefix/suffix when enabled."""
    if not enabled:
        return raw_app, None, None, None

    paren = re.match(r"^(?P<base>.+?)\s*[\(\[](?P<pub>[A-Za-z][A-Za-z0-9&.+ '\-]{1,40})[\)\]]$", raw_app)
    if paren:
        base = normalize_spaces(paren.group("base"))
        pub_raw = normalize_spaces(paren.group("pub"))
        pub_key = app_key(pub_raw)
        publisher = publishers.get(pub_key, pub_raw)
        if base and publisher:
            return base, publisher, "high", f"publisher:{publisher}"

    lowered = raw_app.lower()
    for _pub_key, publisher in sorted(publishers.items(), key=lambda kv: len(kv[1]), reverse=True):
        pub_lower = publisher.lower()
        if not lowered.startswith(pub_lower + " "):
            continue
        base = normalize_spaces(raw_app[len(publisher) :])
        if base and len(base.split()) >= 1:
            return base, publisher, "medium", f"publisher:{publisher}"

    return raw_app, None, None, None


def normalize_app_metadata(
    raw_app: str,
    normalize_editions: bool,
    normalize_publishers: bool,
    publishers: dict[str, str],
) -> tuple[str, str | None, str | None, str | None, list[str]]:
    """Normalize app name and return metadata + confidence + notes."""
    notes: list[str] = []
    confidence_rank = {"low": 1, "medium": 2, "high": 3}
    confidence: str | None = None

    app_name, edition, ed_conf, ed_note = split_app_edition(raw_app, enabled=normalize_editions)
    if ed_note:
        notes.append(ed_note)
    if ed_conf:
        confidence = ed_conf

    app_name, publisher, pub_conf, pub_note = split_publisher(
        app_name, enabled=normalize_publishers, publishers=publishers
    )
    if pub_note:
        notes.append(pub_note)
    if pub_conf and (confidence is None or confidence_rank[pub_conf] > confidence_rank[confidence]):
        confidence = pub_conf

    return app_name, edition, publisher, confidence, notes


def apply_version_prefix_from_tail(raw_app: str, version: str) -> tuple[str, str, str | None]:
    """Move trailing label words from app tail into version when appropriate.

    Example:
    - "Encyclopedie Universalis Edition 2014" ->
      app="Encyclopedie Universalis", version="Edition 2014"
    """
    year_like = re.fullmatch(r"\d{4}(?:\.\d+)?", version) is not None
    if not year_like:
        return raw_app, version, None

    m = re.match(r"^(?P<base>.+?)\s+(?P<label>Edition)$", raw_app, flags=re.IGNORECASE)
    if not m:
        return raw_app, version, None

    base = normalize_spaces(m.group("base"))
    if not base:
        return raw_app, version, None

    label = normalize_edition(m.group("label"))
    return base, f"{label} {version}", f"version-prefix:{label}"


JAVA_JDK_NAME = "JDK - Java Development Kit"
JAVA_JRE_NAME = "JRE - Java Runtime Environment"
JAVA_VERSION_U_RE = re.compile(r"^\d{1,3}u\d{1,4}(?:\.\d+)?$", re.IGNORECASE)
JAVA_VERSION_NUMERIC_RE = re.compile(r"^\d{1,3}(?:\.\d+)*$")


def normalize_java_distribution(app_name: str, version: str | None) -> tuple[str, str | None]:
    """Normalize Java families into JDK/JRE canonical names.

    Rules:
    - explicit jdk/development kit keywords -> JDK family
    - explicit jre/runtime env keywords -> JRE family
    - plain "Java" with `XuY` version (e.g. 8u40) -> JRE family
    """
    key = app_key(app_name)
    note: str | None = None
    target = app_name

    if any(token in key for token in ("jdk", "developmentkit")):
        target = JAVA_JDK_NAME
        note = "java-family:JDK"
    elif any(token in key for token in ("jre", "runtimeenvironment", "runtimeenv")):
        target = JAVA_JRE_NAME
        note = "java-family:JRE"
    elif key == "java" and version and JAVA_VERSION_U_RE.match(version):
        target = JAVA_JRE_NAME
        note = "java-family:JRE"
    elif key == "java" and version and JAVA_VERSION_NUMERIC_RE.match(version):
        major = int(version.split(".")[0])
        if major >= 9:
            target = JAVA_JDK_NAME
            note = "java-family:JDK"

    return target, note


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


def parse_name_and_version(
    entry_name: str,
    normalize_editions: bool,
    normalize_publishers: bool,
    publishers: dict[str, str],
) -> ParseResult | None:
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

    app_name, edition, publisher, confidence, notes = normalize_app_metadata(
        raw_app,
        normalize_editions=normalize_editions,
        normalize_publishers=normalize_publishers,
        publishers=publishers,
    )
    app_name, version, version_note = apply_version_prefix_from_tail(app_name, version)
    if version_note:
        notes.append(version_note)
    app_name, java_note = normalize_java_distribution(app_name, version)
    if java_note:
        notes.append(java_note)
    channel = extract_channel(normalized)
    if channel and publisher and app_key(channel) == app_key(publisher):
        channel = None
    is_update = detect_update_marker(raw_tail)

    return ParseResult(
        app_name=app_name,
        version=version,
        edition=edition,
        publisher=publisher,
        revision=revision,
        is_update=is_update,
        channel=channel,
        normalization_confidence=confidence,
        normalization_notes=notes or None,
    )


def parse_app_name_only(
    entry_name: str,
    normalize_editions: bool,
    normalize_publishers: bool,
    publishers: dict[str, str],
) -> ParseResult | None:
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
    app_name, edition, publisher, confidence, notes = normalize_app_metadata(
        cleaned,
        normalize_editions=normalize_editions,
        normalize_publishers=normalize_publishers,
        publishers=publishers,
    )
    app_name, java_note = normalize_java_distribution(app_name, None)
    if java_note:
        notes.append(java_note)
    return ParseResult(
        app_name=app_name,
        version="",
        edition=edition,
        publisher=publisher,
        normalization_confidence=confidence,
        normalization_notes=notes or None,
    )


def safe_part(part: str) -> str:
    """Sanitize one path segment for conservative macOS-safe naming."""
    cleaned = re.sub(r"[/:]", "-", part).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned[:120] if cleaned else "Unknown"


def app_key(name: str) -> str:
    """Canonical key for grouping variants across punctuation/case changes."""
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def app_path_parts(display_name: str) -> list[str]:
    """Resolve app path parts, optionally with a parent grouping folder."""
    key = app_key(display_name)
    parent = APP_PARENT_GROUPS.get(key)
    if parent:
        return [parent, display_name]
    return [display_name]


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


def load_publishers(path: Path | None) -> dict[str, str]:
    """Load publisher aliases from JSON and merge with built-in publishers."""
    publishers: dict[str, str] = dict(BUILTIN_PUBLISHER_ALIASES)
    if path is None:
        return publishers

    if not path.exists():
        print(f"WARN: publishers file not found: {path} (using built-in publishers only)")
        return publishers

    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except Exception as exc:
        print(f"WARN: failed to read publishers file {path}: {exc} (using built-in publishers only)")
        return publishers

    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, str):
                continue
            key = app_key(entry)
            if key:
                publishers[key] = normalize_spaces(entry)
        return publishers

    if not isinstance(raw, dict):
        print(f"WARN: publishers file {path} must be a JSON array or object; ignoring it")
        return publishers

    for src, dst in raw.items():
        if not isinstance(src, str) or not isinstance(dst, str):
            continue
        src_key = app_key(src)
        dst_name = normalize_spaces(dst)
        if src_key and dst_name:
            publishers[src_key] = dst_name
    return publishers


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


def run_rebucket(root: Path, apply: bool, include_hidden: bool, unknown_dir: str, verbose: bool) -> int:
    """Execute rebucket mode.

    Rebucket mode is independent from parser-based organize mode and only
    reassigns top-level entries to the canonical `*_checked` scheme.
    """
    moved = 0
    skipped = 0
    destination_bucket_dirs = {f"{label}__checked" for label, _ in REBUCKET_SCHEME}

    for src in iter_rebucket_sources(root, include_hidden=include_hidden):
        if src.name == unknown_dir:
            if verbose:
                print(f"SKIP: special folder {src}")
            skipped += 1
            continue

        # Keep canonical destination buckets at root in place.
        if src.parent == root and src.is_dir() and src.name in destination_bucket_dirs:
            if verbose:
                print(f"SKIP: rebucket destination {src}")
            skipped += 1
            continue

        label = rebucket_label_for(src.name)
        target_dir = root / f"{label}__checked"
        if src.parent == target_dir:
            if verbose:
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
    app_base = root
    for part in app_path_parts(app_display_name):
        app_base = app_base / safe_part(part)
    version_part = safe_part(parsed.version)
    if parsed.revision:
        version_part = f"{version_part} [v{safe_part(parsed.revision)}]"
    if parsed.edition:
        version_part = f"{version_part} [{safe_part(parsed.edition)}]"
    if parsed.is_update:
        version_part = f"{version_part} [Update]"
    if parsed.channel:
        version_part = f"{version_part} [{safe_part(parsed.channel)}]"
    if parsed.publisher:
        version_part = f"{version_part} [Publisher:{safe_part(parsed.publisher)}]"
    return app_base / version_part / src_name


def iter_entries(root: Path, include_hidden: bool) -> Iterable[Path]:
    """Iterate top-level entries for organize mode."""
    for item in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not include_hidden and item.name.startswith("."):
            continue
        if item.name == Path(__file__).name:
            continue
        yield item


def visible_children(path: Path) -> list[Path]:
    """Return non-hidden direct children."""
    return [c for c in path.iterdir() if not c.name.startswith(".")]


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


def looks_like_version_dir(path: Path) -> bool:
    """Broader version-like matcher used for container refinement."""
    if not path.is_dir():
        return False
    return VERSION_DIR_RE.match(path.name) is not None or VERSIONISH_DIR_RE.match(path.name) is not None


def iter_unknown_tracks(app_dir: Path, unknown_dir: str) -> Iterable[Path]:
    """Yield unknown tracks for one app container (legacy and configured name)."""
    names = {unknown_dir.lower(), "unknown"}
    for child in sorted(app_dir.iterdir(), key=lambda p: p.name.lower()):
        if child.name.startswith(".") or not child.is_dir():
            continue
        if child.name.lower() in names:
            yield child


def promote_unknown_entries(
    app_dir: Path,
    apply: bool,
    unknown_dir: str,
    aliases: dict[str, str],
    normalize_editions: bool,
    normalize_publishers: bool,
    publishers: dict[str, str],
) -> tuple[int, int]:
    """Promote parseable entries from unknown tracks into app/version structure.

    This pass only inspects direct children of unknown tracks, keeping scope
    intentionally narrow and predictable.
    """
    promoted = 0
    checked = 0
    display_by_key: dict[str, str] = {}

    for track_dir in iter_unknown_tracks(app_dir, unknown_dir=unknown_dir):
        for child in sorted(track_dir.iterdir(), key=lambda p: p.name.lower()):
            if child.name.startswith("."):
                continue
            parsed = parse_name_and_version(
                child.name,
                normalize_editions=normalize_editions,
                normalize_publishers=normalize_publishers,
                publishers=publishers,
            )
            if parsed is None:
                continue
            checked += 1
            key = app_key(parsed.app_name)
            display_by_key[key] = choose_display_name(display_by_key.get(key), parsed.app_name, key, aliases)
            app_display_name = display_by_key[key]
            destination = compute_destination(track_dir, child.name, app_display_name, parsed)
            move_entry(child, destination, apply)
            promoted += 1

    return promoted, checked


def run_audit(
    root: Path,
    include_hidden: bool,
    unknown_dir: str,
    normalize_editions: bool,
    normalize_publishers: bool,
    publishers: dict[str, str],
) -> int:
    """Analyze tree quality and print maintenance-oriented metrics.

    Audit mode never mutates the filesystem. It is intended as a preflight
    report before running organize/promote/refine passes.
    """
    total_dirs = 0
    total_files = 0
    unknown_dirs = 0
    empty_dirs = 0
    wrapper_candidates = 0
    sidecars = 0
    parseable_in_unknown = 0
    unknown_samples: list[str] = []
    wrapper_samples: list[str] = []
    sidecar_samples: list[str] = []
    parseable_unknown_samples: list[str] = []
    depth_counter: Counter[int] = Counter()
    unknown_names = {unknown_dir.lower(), "unknown"}

    for dirpath, dirnames, filenames in os.walk(root):
        dirpath_p = Path(dirpath)
        if not include_hidden:
            dirnames[:] = [d for d in dirnames if not d.startswith(".")]
            filenames = [f for f in filenames if not f.startswith(".")]

        total_dirs += 1
        total_files += len(filenames)
        rel = dirpath_p.relative_to(root) if dirpath_p != root else Path(".")
        depth_counter[len(rel.parts)] += 1

        current_name = dirpath_p.name.lower()
        if current_name in unknown_names:
            unknown_dirs += 1
            if len(unknown_samples) < 8:
                unknown_samples.append(str(dirpath_p))
            for child_name in sorted(dirnames + filenames, key=str.lower):
                parsed = parse_name_and_version(
                    child_name,
                    normalize_editions=normalize_editions,
                    normalize_publishers=normalize_publishers,
                    publishers=publishers,
                )
                if parsed is None:
                    continue
                parseable_in_unknown += 1
                if len(parseable_unknown_samples) < 8:
                    parseable_unknown_samples.append(str(dirpath_p / child_name))

        if not dirnames and not filenames:
            empty_dirs += 1

        for fname in filenames:
            if SIDECAR_RE.search(fname):
                sidecars += 1
                if len(sidecar_samples) < 8:
                    sidecar_samples.append(str(dirpath_p / fname))

        if looks_like_version_dir(dirpath_p) and len(dirnames) == 1 and not filenames:
            child = dirnames[0]
            if re.search(r"\d", child):
                wrapper_candidates += 1
                if len(wrapper_samples) < 8:
                    wrapper_samples.append(str(dirpath_p / child))

    print(
        f"\nSummary (AUDIT): dirs={total_dirs}, files={total_files}, "
        f"unknown_dirs={unknown_dirs}, parseable_in_unknown={parseable_in_unknown}, "
        f"wrapper_candidates={wrapper_candidates}, sidecars={sidecars}, empty_dirs={empty_dirs}, root={root}"
    )
    if depth_counter:
        top_depths = ", ".join(f"d{d}:{c}" for d, c in sorted(depth_counter.items())[:8])
        print(f"Depth histogram: {top_depths}")
    if unknown_samples:
        print("Sample unknown dirs:")
        for sample in unknown_samples:
            print(f"  - {sample}")
    if parseable_unknown_samples:
        print("Sample parseable entries in unknown:")
        for sample in parseable_unknown_samples:
            print(f"  - {sample}")
    if wrapper_samples:
        print("Sample wrapper candidates:")
        for sample in wrapper_samples:
            print(f"  - {sample}")
    if sidecar_samples:
        print("Sample sidecar files:")
        for sample in sidecar_samples:
            print(f"  - {sample}")

    return 0


def refine_app_container(
    app_dir: Path,
    apply: bool,
) -> tuple[int, int]:
    """Flatten one redundant nesting level inside an already-organized app container.

    Example:
    App/2019/2019.16.32/App 2019 16.32/<payload>
    -> App/2019/2019.16.32/<payload>
    """
    fixed = 0
    checked = 0
    app_k = app_key(app_dir.name)

    for track_dir in sorted(app_dir.iterdir(), key=lambda p: p.name.lower()):
        if track_dir.name.startswith(".") or not track_dir.is_dir():
            continue

        for version_dir in sorted(track_dir.iterdir(), key=lambda p: p.name.lower()):
            if version_dir.name.startswith(".") or not looks_like_version_dir(version_dir):
                continue
            checked += 1

            direct_visible = visible_children(version_dir)
            direct_non_dirs = [c for c in direct_visible if not c.is_dir()]
            if direct_non_dirs:
                continue

            direct_dirs = [c for c in direct_visible if c.is_dir()]
            if len(direct_dirs) != 1:
                continue
            wrapper = direct_dirs[0]

            wrapper_k = app_key(wrapper.name)
            if app_k and app_k not in wrapper_k:
                continue
            if not re.search(r"\d", wrapper.name):
                continue

            wrapper_children = visible_children(wrapper)
            if not wrapper_children:
                continue

            print(f"REFINE: flatten wrapper {wrapper} -> {version_dir}")
            for child in wrapper_children:
                move_entry(child, version_dir / child.name, apply)
            fixed += 1

    return fixed, checked


def already_grouped(root: Path, src: Path, app_display_name: str, parsed: ParseResult) -> bool:
    """Return True when entry already matches the expected app/version layout."""
    rel = src.relative_to(root)
    app_parts = [safe_part(p) for p in app_path_parts(app_display_name)]
    if len(rel.parts) < len(app_parts) + 2:
        return False
    version = safe_part(parsed.version)
    if parsed.revision:
        version = f"{version} [v{safe_part(parsed.revision)}]"
    if parsed.edition:
        version = f"{version} [{safe_part(parsed.edition)}]"
    if parsed.is_update:
        version = f"{version} [Update]"
    if parsed.publisher:
        version = f"{version} [Publisher:{safe_part(parsed.publisher)}]"
    for idx, app_part in enumerate(app_parts):
        if app_key(rel.parts[idx]) != app_key(app_part):
            return False
    current_version = rel.parts[len(app_parts)]
    return current_version.startswith(version)


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
    """CLI entrypoint.

    The script defaults to dry-run across all mutating modes; use `--apply`
    only after reviewing planned operations.
    """
    parser = argparse.ArgumentParser(
        description="Organize installers into AppName/Version/<original-file-or-folder>.",
        epilog="Default behavior is dry-run. Use --apply to perform real moves.",
    )
    parser.add_argument("root", nargs="?", default=".", help="Directory to organize (default: current directory)")
    parser.add_argument("--apply", action="store_true", help="Apply filesystem moves (otherwise dry-run)")
    parser.add_argument("--verbose", action="store_true", help="Show SKIP diagnostics and extra context")
    parser.add_argument("--include-hidden", action="store_true", help="Include hidden files and folders")
    parser.add_argument(
        "--rebucket",
        action="store_true",
        help="Re-distribute entries into canonical top-level buckets (A-B__checked, C-D__checked, ...)",
    )
    parser.add_argument("--unknown-dir", default="_Unsorted", help="Folder for entries where version parsing fails")
    parser.add_argument(
        "--no-version-label",
        default="unknown",
        help="Version label for names without parsable version (set empty to keep them in unknown-dir)",
    )
    parser.add_argument(
        "--aliases-file",
        default=None,
        help="Path to JSON alias map, e.g. {'LittleSnitch': 'Little Snitch'}",
    )
    parser.add_argument(
        "--normalize-editions",
        action="store_true",
        help="Split common edition suffixes (Enterprise, Plus, Professional...) into version tags",
    )
    parser.add_argument(
        "--normalize-publishers",
        action="store_true",
        help="Extract publisher prefixes/suffixes (e.g. Roxio Toast -> Toast [Publisher:Roxio])",
    )
    parser.add_argument(
        "--publishers-file",
        default=None,
        help="Path to JSON publisher aliases (array or object) used by --normalize-publishers",
    )
    parser.add_argument(
        "--refine-containers",
        action="store_true",
        help="Flatten one redundant wrapper level inside already-organized app containers",
    )
    parser.add_argument(
        "--promote-unknown",
        action="store_true",
        help="Promote parseable entries from unknown tracks inside already grouped app containers",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Read-only quality report (unknown tracks, wrappers, sidecars, empty dirs)",
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
            verbose=args.verbose,
        )

    aliases = load_aliases(Path(args.aliases_file).expanduser() if args.aliases_file else None)
    publishers = load_publishers(Path(args.publishers_file).expanduser() if args.publishers_file else None)

    if args.audit:
        return run_audit(
            root=root,
            include_hidden=args.include_hidden,
            unknown_dir=args.unknown_dir,
            normalize_editions=args.normalize_editions,
            normalize_publishers=args.normalize_publishers,
            publishers=publishers,
        )
    display_by_key: dict[str, str] = {}

    moved = 0
    skipped = 0
    unsorted = 0
    no_version = 0
    promoted_unknown = 0
    promoted_unknown_checked = 0
    refined = 0
    refined_checked = 0

    for src in iter_entries(root, include_hidden=args.include_hidden):
        if src.name == args.unknown_dir:
            if args.verbose:
                print(f"SKIP: special folder {src}")
            skipped += 1
            continue
        # Safety: when running from a bucketed root, never treat bucket folders
        # themselves as app entries.
        if src.parent == root and src.is_dir() and REBUCKET_DIR_RE.match(src.name):
            if args.verbose:
                print(f"SKIP: rebucket container {src}")
            skipped += 1
            continue
        if looks_like_app_container(src):
            if args.promote_unknown:
                promoted, promoted_checked = promote_unknown_entries(
                    src,
                    args.apply,
                    unknown_dir=args.unknown_dir,
                    aliases=aliases,
                    normalize_editions=args.normalize_editions,
                    normalize_publishers=args.normalize_publishers,
                    publishers=publishers,
                )
                promoted_unknown += promoted
                promoted_unknown_checked += promoted_checked
            if args.refine_containers:
                fixed, checked = refine_app_container(
                    src,
                    args.apply,
                )
                refined += fixed
                refined_checked += checked
                if fixed == 0 and args.verbose:
                    print(f"SKIP: app container {src} (no refinements)")
                continue
            if args.promote_unknown:
                continue
            if args.verbose:
                print(f"SKIP: app container {src}")
            skipped += 1
            continue

        parsed = parse_name_and_version(
            src.name,
            normalize_editions=args.normalize_editions,
            normalize_publishers=args.normalize_publishers,
            publishers=publishers,
        )

        if parsed is None:
            app_only = parse_app_name_only(
                src.name,
                normalize_editions=args.normalize_editions,
                normalize_publishers=args.normalize_publishers,
                publishers=publishers,
            )
            if app_only and args.no_version_label:
                parsed = app_only
                parsed.version = args.no_version_label
                no_version += 1
            else:
                destination = root / args.unknown_dir / src.name
                move_entry(src, destination, args.apply)
                unsorted += 1
                moved += 1
                continue

        if parsed.normalization_notes:
            confidence = parsed.normalization_confidence or "low"
            notes = ", ".join(parsed.normalization_notes)
            print(
                f"NORMALIZE[{confidence.upper()}]: '{src.name}' -> app='{parsed.app_name}'"
                f" edition='{parsed.edition or '-'}' publisher='{parsed.publisher or '-'}' ({notes})"
            )

        key = app_key(parsed.app_name)
        display_by_key[key] = choose_display_name(display_by_key.get(key), parsed.app_name, key, aliases)
        app_display_name = display_by_key[key]

        if already_grouped(root, src, app_display_name, parsed):
            if args.verbose:
                print(f"SKIP: already grouped {src}")
            skipped += 1
            continue

        destination = compute_destination(root, src.name, app_display_name, parsed)
        move_entry(src, destination, args.apply)
        moved += 1

    mode = "APPLY" if args.apply else "DRY-RUN"
    print(
        f"\nSummary ({mode}): moved={moved}, skipped={skipped}, "
        f"unsorted={unsorted}, no_version={no_version}, "
        f"promoted_unknown={promoted_unknown}/{promoted_unknown_checked}, "
        f"refined={refined}/{refined_checked}, root={root}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
