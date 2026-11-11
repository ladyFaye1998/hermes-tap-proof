"""Tap Proof - Hermes plugin.

Registers one tool, ``tap_proof``, in toolset ``tap_proof``. No hooks.

The tool asks a local, isolated, headless Edge (driven by ``browser/probe.cjs``)
whether the element matched by a CSS selector would actually receive a tap at
every viewport width in a range. It never clicks and never mutates the page.

Standard library only. The only process started is the installed ``node``
running the bundled probe; the only files written are receipts and witness
screenshots under the profile-scoped plugin data directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

TOOL_NAME = "tap_proof"
TOOLSET = "tap_proof"

PLUGIN_DIR = Path(__file__).resolve().parent
ENGINE_DIR = PLUGIN_DIR / "browser"
ENGINE_SCRIPT = "probe.cjs"

ENGINE_TIMEOUT_SECONDS = 45
MAX_ENGINE_STDOUT_BYTES = 8 * 1024 * 1024
MAX_WITNESS_BYTES = 32 * 1024 * 1024

MIN_WIDTH_LIMIT = 240
MAX_WIDTH_LIMIT = 2560
MAX_WIDTHS = 800
MIN_HEIGHT = 240
MAX_HEIGHT = 1600
MAX_WITNESS_WIDTHS = 8
DEFAULT_HEIGHT = 760
MAX_URL_CHARS = 2048
MAX_SELECTOR_CHARS = 512

MAX_BANDS_IN_OUTPUT = 24
MAX_RANGES_IN_OUTPUT = 24
MAX_WITNESSES_IN_OUTPUT = 12

STATES = ("pass", "blocked", "inconclusive")
SCAN_FIELDS = ("url", "selector", "min_width", "max_width", "height", "ready_selector")
KNOWN_FIELDS = ("mode", "check_id") + SCAN_FIELDS

# Only what Windows needs to start a process and what the probe needs to find
# the installed Edge. No API keys, proxies, NODE_OPTIONS or other secrets.
ENV_ALLOWLIST = (
    "PATH",
    "HOME",
    "SystemRoot",
    "WINDIR",
    "SystemDrive",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "TEMP",
    "TMP",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "PATHEXT",
    "ComSpec",
)

SETUP_HINT = (
    "Tap Proof needs its local browser engine. In the plugin directory run "
    "`npm ci --prefix browser`, and make sure Microsoft Edge and Node.js 20+ "
    "are installed and `node` is on PATH."
)

_ID_RE = re.compile(r"[0-9a-f]{32}")
_URL_RE = re.compile(r"http://(127\.0\.0\.1|\[::1\]|localhost):([0-9]{1,5})([/?].*)?")
_DEPENDENCY_RE = re.compile(
    r"cannot find module|module_not_found|playwright|puppeteer|msedge|"
    r"executable|edge (is )?not|browser.*not found|unsupported engine",
    re.IGNORECASE,
)

DESCRIPTION = (
    "Tap Proof: prove whether one element on a LOCAL preview page can actually "
    "receive a tap at every viewport width in a range. It loads the page in an "
    "isolated headless Edge, checks each width, and returns a gate: PASS (every "
    "width passes), BLOCKED (at least one width has something covering the "
    "target) or INCONCLUSIVE (some widths could not be decided). The tool never "
    "clicks, never submits forms and never changes the site.\n"
    "Rules: use it only on a local preview URL the user explicitly supplied "
    "(http://127.0.0.1:PORT, http://[::1]:PORT or http://localhost:PORT with an "
    "explicit port). Do not guess or invent URLs or selectors. Report the actual "
    "returned results: the gate, the counts, the blocked width bands with their "
    "culprit element, and any inconclusive widths. Never describe a result as "
    "passing unless gate is exactly PASS; an error is not a pass.\n"
    "mode='scan' runs a new check and returns a check_id. mode='replay' re-runs "
    "a saved check exactly as saved (pass only check_id) and compares against "
    "the first run, which is how you verify a fix."
)

SCHEMA = {
    "name": TOOL_NAME,
    "description": DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["scan", "replay"],
                "description": "scan = new check; replay = re-run a saved check by check_id.",
            },
            "url": {
                "type": "string",
                "maxLength": MAX_URL_CHARS,
                "description": (
                    "scan only. Local preview URL supplied by the user. Must be "
                    "http://127.0.0.1:PORT, http://[::1]:PORT or http://localhost:PORT "
                    "(explicit port, no credentials, no #fragment)."
                ),
            },
            "selector": {
                "type": "string",
                "maxLength": MAX_SELECTOR_CHARS,
                "description": "scan only. CSS selector of the element that must be tappable.",
            },
            "min_width": {
                "type": "integer",
                "minimum": MIN_WIDTH_LIMIT,
                "maximum": MAX_WIDTH_LIMIT,
                "description": "scan only. Smallest viewport width in CSS px.",
            },
            "max_width": {
                "type": "integer",
                "minimum": MIN_WIDTH_LIMIT,
                "maximum": MAX_WIDTH_LIMIT,
                "description": (
                    "scan only. Largest viewport width in CSS px. Every integer width "
                    "from min_width to max_width is checked (at most %d widths)." % MAX_WIDTHS
                ),
            },
            "height": {
                "type": "integer",
                "minimum": MIN_HEIGHT,
                "maximum": MAX_HEIGHT,
                "default": DEFAULT_HEIGHT,
                "description": "scan only. Viewport height in CSS px.",
            },
            "ready_selector": {
                "type": "string",
                "maxLength": MAX_SELECTOR_CHARS,
                "description": "scan only, optional. CSS selector to wait for before measuring.",
            },
            "check_id": {
                "type": "string",
                "description": "replay only. The check_id returned by an earlier scan.",
            },
        },
        "required": ["mode"],
        "additionalProperties": False,
    },
}


class ToolError(Exception):
    """A failure that is reported to the model as a clear, non-passing result."""

    def __init__(self, message, hint=None, **extra):
        super().__init__(message)
        self.message = message
        self.hint = hint
        self.extra = dict(extra)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_text(value, limit=300):
    """Bounded, printable text from untrusted engine output."""
    if not isinstance(value, str):
        return ""
    text = "".join(ch if ch.isprintable() else " " for ch in value).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _has_control_chars(text):
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in text)


def _as_int(value, name):
    if isinstance(value, bool):
        raise ToolError("%s must be an integer." % name)
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    raise ToolError("%s must be an integer." % name)


def _write_json_atomic(path, data):
    path = Path(path)
    tmp = path.with_name("%s.%s.tmp" % (path.name, uuid.uuid4().hex[:8]))
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


def _read_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _sha256_file(path):
    digest = hashlib.sha256()
    remaining = MAX_WITNESS_BYTES
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            remaining -= len(chunk)
            if remaining < 0:
                raise ValueError("witness file too large")
            digest.update(chunk)
    return digest.hexdigest()


def _ranges(widths, limit=MAX_RANGES_IN_OUTPUT):
    """Collapse widths into [[start, end], ...]; returns (ranges, truncated)."""
    out = []
    for width in sorted(widths):
        if out and width == out[-1][1] + 1:
            out[-1][1] = width
        else:
            out.append([width, width])
    return out[:limit], len(out) > limit


def _range_text(ranges):
    return ", ".join("%d" % a if a == b else "%d-%d" % (a, b) for a, b in ranges)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_url(url):
    if not isinstance(url, str) or not url:
        raise ToolError("url is required for scan and must be a string.")
    if len(url) > MAX_URL_CHARS:
        raise ToolError("url is too long (max %d characters)." % MAX_URL_CHARS)
    if any(ord(ch) <= 32 or ord(ch) >= 127 for ch in url) or "\\" in url:
        raise ToolError(
            "url must be plain ASCII with no spaces, control characters or backslashes "
            "(percent-encode anything else)."
        )
    if "#" in url:
        raise ToolError("url must not contain a #fragment.")
    match = _URL_RE.fullmatch(url)
    if not match:
        raise ToolError(
            "url must be a local preview: http://127.0.0.1:PORT, http://[::1]:PORT or "
            "http://localhost:PORT with an explicit port, optional path/query, and no "
            "credentials. Tap Proof does not open any other address."
        )
    port = int(match.group(2))
    if not 1 <= port <= 65535:
        raise ToolError("url port must be between 1 and 65535.")
    # Cross-check with the standard parser so both views of the URL agree.
    try:
        parts = urlsplit(url)
        ok = (
            parts.scheme == "http"
            and parts.username is None
            and parts.password is None
            and parts.hostname in ("127.0.0.1", "::1", "localhost")
            and parts.port == port
            and not parts.fragment
        )
    except ValueError:
        ok = False
    if not ok:
        raise ToolError("url could not be parsed as a plain local http URL.")
    return url


def _validate_selector(value, name, required=True):
    if value is None:
        if required:
            raise ToolError("%s is required for scan." % name)
        return None
    if not isinstance(value, str) or not value.strip():
        raise ToolError("%s must be a non-empty CSS selector string." % name)
    value = value.strip()  # the engine trims selectors; save exactly what it will use
    if len(value) > MAX_SELECTOR_CHARS:
        raise ToolError("%s is too long (max %d characters)." % (name, MAX_SELECTOR_CHARS))
    if _has_control_chars(value):
        raise ToolError("%s must not contain control characters or line breaks." % name)
    return value


def _validate_options(url, selector, min_width, max_width, height, ready_selector):
    """Return the exact engine options (camelCase, without witnessDir)."""
    url = _validate_url(url)
    selector = _validate_selector(selector, "selector")
    if min_width is None or max_width is None:
        raise ToolError("min_width and max_width are required for scan.")
    min_width = _as_int(min_width, "min_width")
    max_width = _as_int(max_width, "max_width")
    for name, value in (("min_width", min_width), ("max_width", max_width)):
        if not MIN_WIDTH_LIMIT <= value <= MAX_WIDTH_LIMIT:
            raise ToolError(
                "%s must be between %d and %d." % (name, MIN_WIDTH_LIMIT, MAX_WIDTH_LIMIT)
            )
    if min_width > max_width:
        raise ToolError("min_width must not be greater than max_width.")
    count = max_width - min_width + 1
    if count > MAX_WIDTHS:
        raise ToolError(
            "Range covers %d widths; at most %d are allowed per check. Narrow the range "
            "or split it into several scans." % (count, MAX_WIDTHS)
        )
    height = DEFAULT_HEIGHT if height is None else _as_int(height, "height")
    if not MIN_HEIGHT <= height <= MAX_HEIGHT:
        raise ToolError("height must be between %d and %d." % (MIN_HEIGHT, MAX_HEIGHT))
    ready_selector = _validate_selector(ready_selector, "ready_selector", required=False)

    options = {
        "url": url,
        "selector": selector,
        "minWidth": min_width,
        "maxWidth": max_width,
        "height": height,
    }
    if ready_selector is not None:
        options["readySelector"] = ready_selector
    return options


def _validate_id(value, name="check_id"):
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ToolError("%s must be the 32-character lowercase hex id returned by a scan." % name)
    return value


def _data_dir(ctx):
    state = getattr(ctx, "state", None)
    data_dir = getattr(state, "data_dir", None)
    if not data_dir:
        raise ToolError("Hermes did not provide a plugin data directory (ctx.state.data_dir).")
    return Path(data_dir)


# ---------------------------------------------------------------------------
# Browser engine
# ---------------------------------------------------------------------------

def _engine_env():
    env = {}
    for name in ENV_ALLOWLIST:
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _find_node(env):
    return shutil.which("node", path=env.get("PATH"))


def _parse_engine_stdout(stdout):
    if isinstance(stdout, bytes):
        if len(stdout) > MAX_ENGINE_STDOUT_BYTES:
            return None
        text = stdout.decode("utf-8", errors="replace")
    else:
        text = stdout or ""
    text = text.strip()
    if not text:
        return None
    candidates = [text]
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) > 1:
        candidates.append(lines[-1])
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    return None


def _run_engine(options, witness_dir, witness_widths=None):
    """Run browser/probe.cjs once and return its parsed ok:true JSON object."""
    script = ENGINE_DIR / ENGINE_SCRIPT
    if not script.is_file():
        raise ToolError("Browser engine file is missing: %s" % script, hint=SETUP_HINT)
    if not (ENGINE_DIR / "node_modules").is_dir():
        raise ToolError("Browser engine dependencies are not installed.", hint=SETUP_HINT)
    env = _engine_env()
    node = _find_node(env)
    if not node:
        raise ToolError("Node.js was not found on PATH.", hint=SETUP_HINT)

    payload = dict(options)
    payload["witnessDir"] = str(witness_dir)
    if witness_widths:
        payload["witnessWidths"] = list(witness_widths)
    line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")

    try:
        proc = subprocess.run(
            [node, str(script)],
            input=line,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PLUGIN_DIR),
            env=env,
            shell=False,
            timeout=ENGINE_TIMEOUT_SECONDS,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        raise ToolError(
            "Browser engine timed out after %d seconds; no verdict was produced. Check that "
            "the local preview is running and responsive, or scan a narrower width range."
            % ENGINE_TIMEOUT_SECONDS
        )
    except OSError as exc:
        raise ToolError("Could not start Node.js: %s" % _clean_text(str(exc)), hint=SETUP_HINT)

    stderr = proc.stderr
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", errors="replace")
    stderr_tail = _clean_text((stderr or "")[-600:], 600)

    data = _parse_engine_stdout(proc.stdout)
    if data is None:
        detail = "exit code %s" % proc.returncode
        if stderr_tail:
            detail += "; stderr: " + stderr_tail
        raise ToolError(
            "Browser engine returned no readable result (%s)." % detail, hint=SETUP_HINT
        )
    if data.get("ok") is not True:
        error = _clean_text(data.get("error"), 500) or "engine reported a failure without detail"
        hint = SETUP_HINT if _DEPENDENCY_RE.search(error + " " + stderr_tail) else None
        raise ToolError("Browser engine error: %s" % error, hint=hint)
    if proc.returncode != 0:
        raise ToolError(
            "Browser engine exited with code %s after reporting a result; the result is "
            "not trusted." % proc.returncode
        )
    return data


# ---------------------------------------------------------------------------
# Result interpretation
# ---------------------------------------------------------------------------

def _clean_culprit(value):
    if not isinstance(value, dict):
        return None
    culprit = {}
    for key in ("tag", "id", "selector"):
        text = _clean_text(value.get(key), 200)
        if text:
            culprit[key] = text
    classes = value.get("classes")
    if isinstance(classes, str):
        classes = classes.split()
    if isinstance(classes, list):
        cleaned = [_clean_text(item, 80) for item in classes[:12]]
        cleaned = [item for item in cleaned if item]
        if cleaned:
            culprit["classes"] = cleaned
    return culprit or None


def _normalize_rows(raw, options):
    """Validate engine rows by width. Returns (rows, missing_widths).

    Every width in the requested range gets exactly one row. A width the engine
    did not report is recorded as inconclusive so it can never count as a pass.
    """
    rows = raw.get("rows")
    if not isinstance(rows, list):
        raise ToolError("Browser engine result has no per-width rows; no verdict was produced.")
    if len(rows) > MAX_WIDTHS:
        raise ToolError("Browser engine returned more than %d rows; result rejected." % MAX_WIDTHS)

    lo, hi = options["minWidth"], options["maxWidth"]
    by_width = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ToolError("Browser engine returned a malformed row; result rejected.")
        width = row.get("width")
        if isinstance(width, bool) or not isinstance(width, int):
            raise ToolError("Browser engine returned a row without an integer width.")
        if not lo <= width <= hi:
            raise ToolError(
                "Browser engine returned width %d outside the requested %d-%d range." % (width, lo, hi)
            )
        if width in by_width:
            raise ToolError("Browser engine returned width %d more than once." % width)
        state = row.get("state")
        reason = _clean_text(row.get("reason"))
        if state not in STATES:
            reason = "engine returned an unknown state (%s)" % (_clean_text(str(state), 40) or "none")
            state = "inconclusive"
        entry = {"width": width, "state": state, "reason": reason}
        culprit = _clean_culprit(row.get("culprit"))
        if culprit and state != "pass":
            entry["culprit"] = culprit
        by_width[width] = entry

    missing = []
    normalized = []
    for width in range(lo, hi + 1):
        entry = by_width.get(width)
        if entry is None:
            missing.append(width)
            entry = {
                "width": width,
                "state": "inconclusive",
                "reason": "engine returned no result for this width",
            }
        normalized.append(entry)
    return normalized, missing


def _build_bands(rows):
    bands = []
    for row in rows:
        culprit = row.get("culprit")
        key = (row["state"], row["reason"], json.dumps(culprit, sort_keys=True))
        if bands and bands[-1]["_key"] == key and bands[-1]["end"] + 1 == row["width"]:
            bands[-1]["end"] = row["width"]
            continue
        band = {
            "_key": key,
            "start": row["width"],
            "end": row["width"],
            "state": row["state"],
            "reason": row["reason"],
        }
        if culprit:
            band["culprit"] = culprit
        bands.append(band)
    for band in bands:
        del band["_key"]
        band["widths"] = band["end"] - band["start"] + 1
    return bands


def _collect_witnesses(raw, witness_dir, options):
    """Keep only witness files that really exist inside this run's witness dir."""
    items = raw.get("witnesses")
    if not isinstance(items, list):
        return [], 0
    try:
        root = Path(witness_dir).resolve()
    except OSError:
        return [], len(items)
    witnesses = []
    rejected = 0
    seen = set()
    for item in items[:MAX_WIDTHS]:
        try:
            width = item.get("width")
            raw_path = item.get("path")
            if isinstance(width, bool) or not isinstance(width, int):
                raise ValueError("width")
            if not options["minWidth"] <= width <= options["maxWidth"] or width in seen:
                raise ValueError("width")
            if not isinstance(raw_path, str) or not raw_path or len(raw_path) > 1024:
                raise ValueError("path")
            path = Path(raw_path)
            if not path.is_absolute():
                path = root / path
            path = path.resolve()
            if path == root or root not in path.parents or not path.is_file():
                raise ValueError("path")
            digest = _sha256_file(path)
        except (AttributeError, ValueError, OSError):
            rejected += 1
            continue
        seen.add(width)
        state = item.get("state")
        claimed = item.get("sha256")
        witnesses.append(
            {
                "width": width,
                "state": state if state in STATES else "inconclusive",
                "reason": _clean_text(item.get("reason")),
                "path": str(path),
                "sha256": digest,
                "sha256_matches_engine": isinstance(claimed, str) and claimed.lower() == digest,
            }
        )
    witnesses.sort(key=lambda entry: entry["width"])
    return witnesses, rejected


def _build_report(raw, options, witness_dir):
    rows, missing = _normalize_rows(raw, options)
    counts = {"total": len(rows), "pass": 0, "blocked": 0, "inconclusive": 0}
    for row in rows:
        counts[row["state"]] += 1
    counts["missing"] = len(missing)

    if counts["blocked"]:
        gate = "BLOCKED"
    elif counts["pass"] == counts["total"] and counts["total"] > 0:
        gate = "PASS"
    else:
        gate = "INCONCLUSIVE"

    bands = _build_bands(rows)
    witnesses, rejected = _collect_witnesses(raw, witness_dir, options)

    engine = raw.get("engine") if isinstance(raw.get("engine"), dict) else {}
    notes = []
    for key in ("selector", "height"):
        if key in raw and raw[key] != options[key]:
            notes.append("engine echoed a different %s than requested" % key)
    if missing:
        notes.append(
            "engine returned no result for %d width(s); they are counted as inconclusive"
            % len(missing)
        )
    if rejected:
        notes.append("%d witness entr%s could not be verified on disk and were dropped"
                     % (rejected, "y" if rejected == 1 else "ies"))
    if notes and gate == "PASS" and any("echoed" in note for note in notes):
        gate = "INCONCLUSIVE"

    return {
        "gate": gate,
        "counts": counts,
        "rows": rows,
        "bands": bands,
        "witnesses": witnesses,
        "missing_widths": missing,
        "engine": {
            "name": _clean_text(engine.get("name"), 80) or "unknown",
            "version": _clean_text(str(engine.get("version") or ""), 80) or "unknown",
        },
        "notes": notes,
    }


def _summary(report, options):
    counts = report["counts"]
    text = "%s: %d of %d widths pass, %d blocked, %d inconclusive (%d-%dpx wide, %dpx tall, selector %s)." % (
        report["gate"],
        counts["pass"],
        counts["total"],
        counts["blocked"],
        counts["inconclusive"],
        options["minWidth"],
        options["maxWidth"],
        options["height"],
        options["selector"],
    )
    blocked = [band for band in report["bands"] if band["state"] == "blocked"]
    if blocked:
        worst = max(blocked, key=lambda band: band["widths"])
        culprit = (worst.get("culprit") or {}).get("selector") or (worst.get("culprit") or {}).get("tag")
        text += " Largest blocked band: %d-%dpx" % (worst["start"], worst["end"])
        if culprit:
            text += " covered by %s" % culprit
        if worst["reason"]:
            text += " (%s)" % worst["reason"]
        text += "."
    if counts["inconclusive"]:
        text += " Inconclusive widths are not passes and must be disclosed."
    text += " No clicks were made."
    return text


# ---------------------------------------------------------------------------
# Replay comparison
# ---------------------------------------------------------------------------

def _compare(baseline, report):
    """Compare this run with the first (baseline) run of the same check."""
    before = {}
    for row in baseline.get("rows") or []:
        if isinstance(row, dict) and isinstance(row.get("width"), int):
            before[row["width"]] = row.get("state")
    fixed, regressed, other = [], [], []
    for row in report["rows"]:
        old, new = before.get(row["width"]), row["state"]
        if old is None or old == new:
            continue
        if new == "pass" and old == "blocked":
            fixed.append(row["width"])
        elif new == "blocked":
            regressed.append(row["width"])
        else:
            other.append(row["width"])

    old_hashes = {}
    for item in baseline.get("witnesses") or []:
        if isinstance(item, dict) and isinstance(item.get("width"), int):
            old_hashes[item["width"]] = item.get("sha256")
    witness_changes = []
    for item in report["witnesses"]:
        if item["width"] in old_hashes:
            witness_changes.append(
                {
                    "width": item["width"],
                    "baseline_sha256": old_hashes[item["width"]],
                    "sha256": item["sha256"],
                    "png_bytes": "identical" if old_hashes[item["width"]] == item["sha256"] else "different",
                }
            )

    comparison = {
        "available": True,
        "baseline_run_id": baseline.get("run_id"),
        "baseline_at": baseline.get("finished_at"),
        "baseline_gate": baseline.get("gate"),
        "gate_now": report["gate"],
        "baseline_counts": baseline.get("counts"),
        "changed_widths": len(fixed) + len(regressed) + len(other),
    }
    for name, widths in (
        ("fixed_blocked_to_pass", fixed),
        ("newly_blocked", regressed),
        ("other_changes", other),
    ):
        ranges, truncated = _ranges(widths)
        comparison[name] = {"count": len(widths), "ranges": ranges}
        if truncated:
            comparison[name]["truncated"] = True
    if witness_changes:
        comparison["witnesses_at_same_width"] = witness_changes[:MAX_WITNESSES_IN_OUTPUT]
    return comparison


def _load_baseline(check_dir):
    try:
        pointer = _read_json(check_dir / "baseline.json")
        run_id = pointer.get("run_id")
        if not isinstance(run_id, str) or not _ID_RE.fullmatch(run_id):
            return None
        data = _read_json(check_dir / "runs" / run_id / "result.json")
        return data if isinstance(data, dict) and data.get("ok") is True else None
    except (OSError, ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

def _normalize_args(args):
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except ValueError:
            raise ToolError("Arguments must be a JSON object.")
    if args is None:
        args = {}
    if not isinstance(args, dict):
        raise ToolError("Arguments must be a JSON object.")
    args = {key: value for key, value in args.items() if value is not None}
    unknown = sorted(str(key) for key in args if key not in KNOWN_FIELDS)
    if unknown:
        raise ToolError(
            "Unknown argument(s): %s. Allowed: %s."
            % (", ".join(_clean_text(key, 40) for key in unknown[:8]), ", ".join(KNOWN_FIELDS))
        )
    return args


def _execute(ctx, args):
    args = _normalize_args(args)
    mode = args.get("mode")
    if mode not in ("scan", "replay"):
        raise ToolError("mode must be 'scan' or 'replay'.")

    checks_root = _data_dir(ctx) / "checks"

    if mode == "scan":
        if "check_id" in args:
            raise ToolError(
                "check_id is only for mode='replay'. A scan always creates a new check."
            )
        options = _validate_options(
            args.get("url"),
            args.get("selector"),
            args.get("min_width"),
            args.get("max_width"),
            args.get("height"),
            args.get("ready_selector"),
        )
        check_id = uuid.uuid4().hex
        check_dir = checks_root / check_id
        try:
            check_dir.mkdir(parents=True, exist_ok=False)
            _write_json_atomic(
                check_dir / "check.json",
                {"schema": 1, "check_id": check_id, "created_at": _now(), "options": options},
            )
        except OSError as exc:
            raise ToolError("Could not save the check: %s" % _clean_text(str(exc)))
    else:
        overrides = [name for name in SCAN_FIELDS if name in args]
        if overrides:
            raise ToolError(
                "Replay re-runs a saved check exactly as saved, so it does not accept %s. "
                "Pass only check_id, or run a new scan to change settings." % ", ".join(overrides)
            )
        if "check_id" not in args:
            raise ToolError("check_id is required for mode='replay'.")
        check_id = _validate_id(args["check_id"])
        check_dir = checks_root / check_id
        if not (check_dir / "check.json").is_file():
            raise ToolError("No saved check with check_id %s in this profile." % check_id)
        try:
            saved = _read_json(check_dir / "check.json")
            stored = saved["options"]
            options = _validate_options(
                stored.get("url"),
                stored.get("selector"),
                stored.get("minWidth"),
                stored.get("maxWidth"),
                stored.get("height"),
                stored.get("readySelector"),
            )
            if options != stored or saved.get("check_id") != check_id:
                raise ValueError("saved options are not in canonical form")
        except ToolError as exc:
            raise ToolError("Saved check %s is no longer valid: %s" % (check_id, exc.message))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            raise ToolError("Saved check %s is unreadable or corrupt; run a new scan." % check_id)

    run_id = uuid.uuid4().hex
    run_dir = check_dir / "runs" / run_id
    witness_dir = run_dir / "witnesses"
    started_at = _now()
    try:
        witness_dir.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise ToolError("Could not create the run directory: %s" % _clean_text(str(exc)), check_id=check_id)

    # Replay asks for screenshots at the baseline's witness widths (blocked ones
    # first) so evidence stays same-width even when every width now passes.
    # Ephemeral: never saved into check.json.
    baseline = _load_baseline(check_dir)
    witness_widths = []
    if mode == "replay" and baseline is not None:
        saved_witnesses = [
            item for item in (baseline.get("witnesses") or []) if isinstance(item, dict)
        ]
        saved_witnesses.sort(key=lambda item: item.get("state") != "blocked")
        for item in saved_witnesses:
            width = item.get("width")
            if (
                isinstance(width, int)
                and not isinstance(width, bool)
                and options["minWidth"] <= width <= options["maxWidth"]
                and width not in witness_widths
            ):
                witness_widths.append(width)
            if len(witness_widths) >= MAX_WITNESS_WIDTHS:
                break

    receipt = run_dir / "result.json"
    try:
        raw = _run_engine(options, witness_dir, witness_widths or None)
        report = _build_report(raw, options, witness_dir)
    except ToolError as exc:
        exc.extra.update({"mode": mode, "check_id": check_id, "run_id": run_id})
        try:
            failure = {
                "ok": False,
                "gate": "ERROR",
                "error": exc.message,
                "mode": mode,
                "check_id": check_id,
                "run_id": run_id,
                "started_at": started_at,
                "finished_at": _now(),
                "options": options,
            }
            _write_json_atomic(receipt, failure)
            exc.extra["receipt"] = str(receipt)
        except OSError:
            pass
        raise

    comparison = None
    if mode == "replay":
        if baseline is not None:
            comparison = _compare(baseline, report)
        else:
            comparison = {
                "available": False,
                "note": "The original scan did not complete, so this run becomes the baseline.",
            }

    summary = _summary(report, options)
    full = {
        "ok": True,
        "tool": TOOL_NAME,
        "mode": mode,
        "gate": report["gate"],
        "summary": summary,
        "check_id": check_id,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": _now(),
        "options": options,
        "counts": report["counts"],
        "engine": report["engine"],
        "notes": report["notes"],
        "clicked": False,
        "rows": report["rows"],
        "bands": report["bands"],
        "witnesses": report["witnesses"],
        "witness_dir": str(witness_dir),
    }
    if comparison is not None:
        full["comparison"] = comparison

    notes = list(report["notes"])
    receipt_path = None
    try:
        _write_json_atomic(receipt, full)
        receipt_path = str(receipt)
        if baseline is None:
            _write_json_atomic(check_dir / "baseline.json", {"run_id": run_id, "set_at": _now()})
    except OSError as exc:
        notes.append("receipt could not be written: %s" % _clean_text(str(exc)))

    non_pass = [band for band in report["bands"] if band["state"] != "pass"]
    inconclusive_widths = [row["width"] for row in report["rows"] if row["state"] == "inconclusive"]
    inconclusive_ranges, inconclusive_truncated = _ranges(inconclusive_widths)

    out = {
        "ok": True,
        "mode": mode,
        "gate": report["gate"],
        "summary": summary,
        "check_id": check_id,
        "run_id": run_id,
        "url": options["url"],
        "selector": options["selector"],
        "min_width": options["minWidth"],
        "max_width": options["maxWidth"],
        "height": options["height"],
        "counts": report["counts"],
        "non_pass_bands": non_pass[:MAX_BANDS_IN_OUTPUT],
        "non_pass_bands_total": len(non_pass),
        "non_pass_bands_truncated": len(non_pass) > MAX_BANDS_IN_OUTPUT,
        "inconclusive_widths": {
            "count": len(inconclusive_widths),
            "ranges": inconclusive_ranges,
            "truncated": inconclusive_truncated,
        },
        "witnesses": report["witnesses"][:MAX_WITNESSES_IN_OUTPUT],
        "witnesses_total": len(report["witnesses"]),
        "witness_dir": str(witness_dir),
        "receipt": receipt_path,
        "engine": report["engine"],
        "clicked": False,
    }
    if "readySelector" in options:
        out["ready_selector"] = options["readySelector"]
    if inconclusive_widths:
        out["disclose"] = (
            "%d width(s) were inconclusive (%s%s). Tell the user these widths are unproven."
            % (
                len(inconclusive_widths),
                _range_text(inconclusive_ranges),
                ", ..." if inconclusive_truncated else "",
            )
        )
    if notes:
        out["notes"] = notes
    if comparison is not None:
        out["comparison"] = comparison
    if mode == "scan":
        out["next"] = (
            "After the page is changed, call tap_proof with mode='replay' and "
            "check_id='%s' to re-run this exact check and compare." % check_id
        )
    return out


def _error_output(exc):
    out = {"ok": False, "gate": "ERROR", "error": exc.message}
    if exc.hint:
        out["hint"] = exc.hint
    out.update(exc.extra)
    out["clicked"] = False
    out["note"] = "No verdict was produced. Report this error; do not describe the check as passing."
    return out


def register(ctx):
    """Hermes plugin entry point: one tool, no hooks."""

    def handler(args=None, **kwargs):
        try:
            out = _execute(ctx, args)
        except ToolError as exc:
            out = _error_output(exc)
        except Exception as exc:  # never leak a traceback or a false verdict to the model
            out = _error_output(
                ToolError("Unexpected %s: %s" % (type(exc).__name__, _clean_text(str(exc))))
            )
        return json.dumps(out, ensure_ascii=False)

    ctx.register_tool(
        name=TOOL_NAME,
        toolset=TOOLSET,
        schema=SCHEMA,
        handler=handler,
    )
