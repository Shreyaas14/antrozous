"""Inspect code diffs arriving in messages, before a human is asked to trust one.

A diff is the payload where the approval gate matters most and where the reviewer's
guard is lowest: they asked for it, they want to apply it, and they are skimming.
So this exists to make the dangerous parts of a patch VISIBLE, not to decide
whether the patch is safe — nothing here can tell an honest refactor from a
backdoor. That judgement stays with the person reading it.

What it does catch is the class of attack aimed squarely at review itself: text
that renders differently from how it would compile or apply.

Nothing here applies anything. Received diffs are text.
"""

import re
import unicodedata

# Trojan Source (CVE-2021-42574). Bidi overrides reorder how a line DISPLAYS
# without changing what a compiler sees, so a reviewer can read an innocent
# comment where an executable statement will land. This is the one check that
# defends the review step rather than the machine.
BIDI = {
    "‪",
    "‫",
    "‬",
    "‭",
    "‮",  # embeddings / overrides
    "⁦",
    "⁧",
    "⁨",
    "⁩",  # isolates
    "؜",  # arabic letter mark
}

# Invisible in every editor and terminal, legal in identifiers in several
# languages. Two functions whose names differ only by U+200B are two functions.
INVISIBLE = {"​", "‌", "‍", "﻿", "⁠"}

MAX_BYTES = 256 * 1024
MAX_FILES = 100

_GIT_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_OLD = re.compile(r"^--- (?:a/)?(.*)$")
_NEW = re.compile(r"^\+\+\+ (?:b/)?(.*)$")
_MODE = re.compile(r"^(new file|deleted file|old|new) mode (\d+)$")

# git stores a symlink as a file whose CONTENT is the target path. A patch that
# creates one is a patch that can point anywhere on the filesystem.
SYMLINK_MODE = "120000"


def looks_like_diff(text):
    """Cheap test for whether a message body contains a patch at all."""
    if not isinstance(text, str):
        return False
    return bool(
        re.search(r"^diff --git ", text, re.M)
        or (re.search(r"^--- ", text, re.M) and re.search(r"^\+\+\+ ", text, re.M))
    )


def _unsafe_path(path):
    """Why this path must not be written, or None if it is ordinary."""
    if path == "/dev/null":
        return None
    if not path.strip():
        # `--- ` with nothing after it still produces a file entry, so an empty
        # target has to be an error rather than a path that happens to be fine.
        return "empty path — not a real patch target"
    if path.startswith("/"):
        return "absolute path"
    if "\\" in path:
        return "backslash in path"
    parts = path.split("/")
    if ".." in parts:
        return "escapes the repository with '..'"
    if parts[0] == ".git" or ".git" in parts:
        # Writing .git/hooks/* is remote code execution on the next git command.
        # Never rely on `git apply` to refuse this for us.
        return "writes inside .git/ (hooks here run automatically — this is RCE)"
    if any(unicodedata.category(c) == "Cc" for c in path):
        return "control characters in path"
    return None


def _hidden_characters(text):
    """(line number, description) for anything that hides from a reader."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        bidi = sorted(BIDI & set(line))
        invisible = sorted(INVISIBLE & set(line))
        if bidi:
            found.append(
                (
                    n,
                    "bidirectional override %s — this line may DISPLAY differently "
                    "from how it compiles (Trojan Source)"
                    % " ".join("U+%04X" % ord(c) for c in bidi),
                )
            )
        if invisible:
            found.append(
                (
                    n,
                    "invisible character %s — cannot be seen in any editor"
                    % " ".join("U+%04X" % ord(c) for c in invisible),
                )
            )
    return found


def inspect(text):
    """(files, problems) for a message body containing a patch.

    `files` is what the patch would DO, in the terms a skimming reviewer misses:
    which paths, how many lines, and whether anything is created, deleted, made
    executable, or turned into a symlink.

    `problems` is non-empty when the patch should not be trusted at face value.
    It never means "safe" when empty — only that these particular traps are absent.
    """
    problems = []
    if not isinstance(text, str):
        return [], ["not text"]

    encoded = text.encode("utf-8", "surrogatepass")
    if len(encoded) > MAX_BYTES:
        problems.append(
            "patch is %d bytes; refusing over %d" % (len(encoded), MAX_BYTES)
        )
        return [], problems

    for line_no, why in _hidden_characters(text):
        problems.append("line %d: %s" % (line_no, why))

    files, current = [], None
    for line in text.splitlines():
        header = _GIT_HEADER.match(line)
        if header:
            current = {
                "path": header.group(2),
                "added": 0,
                "removed": 0,
                "new": False,
                "deleted": False,
                "mode": None,
                "symlink": False,
            }
            files.append(current)
            continue

        mode = _MODE.match(line)
        if mode and current is not None:
            kind, bits = mode.groups()
            if kind == "new file":
                current["new"] = True
            elif kind == "deleted file":
                current["deleted"] = True
            if bits.endswith(SYMLINK_MODE):
                current["symlink"] = True
            if kind in ("new", "new file"):
                current["mode"] = bits
            continue

        old, new = _OLD.match(line), _NEW.match(line)
        if new:
            if current is None:
                current = {
                    "path": new.group(1),
                    "added": 0,
                    "removed": 0,
                    "new": False,
                    "deleted": False,
                    "mode": None,
                    "symlink": False,
                }
                files.append(current)
            if new.group(1) == "/dev/null":
                current["deleted"] = True
            elif current.get("path") in (None, "/dev/null"):
                current["path"] = new.group(1)
            continue
        if old:
            if old.group(1) == "/dev/null" and current is not None:
                current["new"] = True
            continue

        if current is None:
            continue
        if line.startswith("+"):
            current["added"] += 1
        elif line.startswith("-"):
            current["removed"] += 1

    if not files:
        problems.append("does not parse as a unified diff")
        return files, problems

    if len(files) > MAX_FILES:
        problems.append("touches %d files; refusing over %d" % (len(files), MAX_FILES))

    for f in files:
        why = _unsafe_path(f["path"])
        if why:
            problems.append("%s: %s" % (f["path"], why))
        if f["symlink"]:
            problems.append(
                "%s: creates a SYMLINK, which can point anywhere" % f["path"]
            )

    return files, problems


def summarize(files, problems):
    """The consequences of a patch, above the patch, in a reviewer's terms."""
    lines = []
    if problems:
        lines.append("!! REFUSED — this patch does something a patch should not:")
        lines.extend("     - %s" % p for p in problems)
        lines.append("")
        lines.append("   The body is shown below UNCHANGED so you can see why.")
        lines.append("   Do not apply it.")
        return "\n".join(lines)

    lines.append("PATCH — %d file(s). Applying it would:" % len(files))
    for f in files:
        flags = []
        if f["new"]:
            flags.append("NEW FILE")
        if f["deleted"]:
            flags.append("DELETES FILE")
        if f["mode"] and f["mode"].endswith("755"):
            flags.append("EXECUTABLE")
        note = ("  [%s]" % ", ".join(flags)) if flags else ""
        lines.append("   %s  +%d -%d%s" % (f["path"], f["added"], f["removed"], note))
    lines.append("")
    lines.append(
        "   Nothing is applied by accepting. This only puts the text in context; "
        "applying is a separate step you take yourself."
    )
    return "\n".join(lines)
