#!/usr/bin/env python3
"""Generate Little Snitch .lsrules files.

The script:
- reads existing rules for metadata and grouping
- reads the current Little Snitch configuration
- filters, groups, normalizes, and deduplicates rules
- consolidates port ranges
- writes rules to --output-dir (default: ./output)

See --help for usage.
"""

import argparse
import glob
import calendar
import json
import plistlib
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
UNUSED_MONTHS = 12
DEFAULT_RULES_DIR = Path("rules")
DEFAULT_OUTPUT_DIR = Path("output")
AGGREGATE_FILE = "all.lsrules"
APPLE_MARKER = "apps developed by apple"
EXCLUDED_TYPES = {"builtinICloudServices", "builtinMacOSServices"}
REMOTE_KEYS = ("remote-domains", "remote-hosts", "remote-addresses", "remote")
KEY_ORDER = ("action", "process", *REMOTE_KEYS, "protocol", "ports")
INTERNAL_KEYS = {
    "uid", "uuid", "id", "created", "modified", "creationDate", "modificationDate",
    "annotation", "factoryHelpText",
    "owner", "profile", "group", "origin", "protected", "disabled", "lastUsed", "useCount",
}

def die(message):
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)

def load_json(path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        die(f"file not found: {path}")
    except json.JSONDecodeError as e:
        die(f"invalid JSON in {path}: {e}")

def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

def normalize(value):
    if isinstance(value, str):
        value = value.strip()
        home = str(Path.home())
        if value == home:
            return "~"
        if home and value.startswith(home + "/"):
            return "~" + value[len(home):]
        return value
    if isinstance(value, list):
        values = [normalize(v) for v in value]
        return sorted(values, key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False))
    if isinstance(value, dict):
        return {k: normalize(v) for k, v in value.items()}
    return value

def clean_rule(rule):
    rule = {k: normalize(v) for k, v in rule.items() if k not in INTERNAL_KEYS and v is not None}
    if "port" in rule and "ports" not in rule:
        rule["ports"] = rule.pop("port")
    if "remote-addresses" in rule:
        value = rule["remote-addresses"]
        values = value if isinstance(value, list) else [value]
        expanded = []
        for item in values:
            if isinstance(item, str):
                expanded.extend(part.strip() for part in item.split(",") if part.strip())
            else:
                expanded.append(item)
        rule["remote-addresses"] = sorted(
            set(expanded),
            key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False),
        )
    return rule

def rule_key(rule):
    return json.dumps(clean_rule(rule), sort_keys=True, ensure_ascii=False, separators=(",", ":"))

def dedupe(rules):
    result, seen = [], set()
    for rule in rules:
        rule = clean_rule(rule)
        key = rule_key(rule)
        if key not in seen:
            seen.add(key)
            result.append(rule)
    return result

def ports(value):
    if isinstance(value, int):
        value = str(value)
    if isinstance(value, list):
        parts = []
        for item in value:
            if isinstance(item, int):
                parts.append(str(item))
            elif isinstance(item, str):
                parts.extend(re.split(r"[,\s]+", item.strip()))
            else:
                return None
    elif isinstance(value, str):
        if not value.strip() or value.strip().lower() == "any":
            return None
        parts = re.split(r"[,\s]+", value.strip())
    else:
        return None
    result = []
    for part in parts:
        if not part:
            continue
        match = re.fullmatch(r"(\d+)(?:\s*-\s*(\d+))?", part)
        if not match:
            return None
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if not (0 <= start <= 65535 and 0 <= end <= 65535):
            return None
        result.append((min(start, end), max(start, end)))
    return result or None

def merge_ranges(ranges):
    result = []
    for start, end in sorted(ranges):
        if result and start <= result[-1][1] + 1:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([start, end])
    return result

def format_ports(ranges):
    return ",".join(str(a) if a == b else f"{a}-{b}" for a, b in merge_ranges(ranges))

def merge_values(a, b, split_commas=False):
    values = a if isinstance(a, list) else [a]
    values += b if isinstance(b, list) else [b]
    if split_commas:
        expanded = []
        for value in values:
            if isinstance(value, str):
                expanded.extend(part.strip() for part in value.split(",") if part.strip())
            else:
                expanded.append(value)
        values = expanded
    unique = {json.dumps(normalize(v), sort_keys=True, ensure_ascii=False): normalize(v) for v in values}
    return sorted(unique.values(), key=lambda v: json.dumps(v, sort_keys=True, ensure_ascii=False))

def consolidate(rules):
    # Merge rules with the same semantics but different endpoints.
    endpoint_groups = {}
    for rule in dedupe(rules):
        remote = next((k for k in REMOTE_KEYS if k in rule), None)
        base = dict(rule)
        if remote:
            base.pop(remote)
        key = json.dumps(base, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if remote:
            key = remote + "\0" + key
        if key not in endpoint_groups:
            endpoint_groups[key] = dict(rule)
        elif remote:
            endpoint_groups[key][remote] = merge_values(
                endpoint_groups[key][remote], rule[remote], split_commas=(remote == "remote-addresses")
            )
    # Merge ports only when every other property is identical.
    groups, result = {}, []
    for rule in endpoint_groups.values():
        if "ports" not in rule or ports(rule["ports"]) is None:
            result.append(rule)
            continue
        base = dict(rule)
        port_ranges = ports(base.pop("ports"))
        key = json.dumps(base, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        if key not in groups:
            groups[key] = (dict(rule), [])
        groups[key][1].extend(port_ranges)
    for rule, ranges in groups.values():
        rule["ports"] = format_ports(ranges)
        result.append(rule)
    return dedupe(result)

def canonicalize(rules):
    rules = consolidate(rules)
    def sort_key(rule):
        values = [json.dumps(rule.get(k, ""), sort_keys=True, ensure_ascii=False) for k in KEY_ORDER]
        return (*values, rule_key(rule))
    rules.sort(key=sort_key)
    return [{**{k: rule[k] for k in KEY_ORDER if k in rule}, **{k: rule[k] for k in sorted(rule) if k not in KEY_ORDER}} for rule in rules]

def resolve_process(process, executables):
    if not isinstance(process, str):
        return process
    if process.startswith("identifier."):
        identifier = process[len("identifier."):]
        return executables.get(identifier, process)
    return process

def app_name(process, executables=None):
    process = resolve_process(process, executables or {})
    if not isinstance(process, str) or process == "any":
        return None
    match = re.search(r"^(.+?\.app)(?:/.*)?$", process)
    name = Path(match.group(1)).stem if match else Path(process).name
    if not name:
        return None
    if re.fullmatch(r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+", name):
        name = name.rsplit(".", 1)[-1]
    return re.sub(r"\s+", " ", name).strip() or None

def app_key(name):
    return re.sub(r"[^a-z0-9]+", "", re.sub(r"\.lsrules$|\.rules$", "", name, flags=re.I).lower())

def bundle(process, executables=None):
    process = resolve_process(process, executables or {})
    if not isinstance(process, str):
        return None
    match = re.search(r"^(.+?\.app)(?:/.*)?$", process)
    return Path(match.group(1)) if match else None

def is_apple_identifier(process):
    return isinstance(process, str) and process.casefold().startswith("identifier.apple/")

def is_apple_app(process, executables=None):
    resolved = resolve_process(process, executables or {})
    app = bundle(resolved, executables)
    if not app:
        return False
    if str(app).startswith("/System/Applications/") or str(app).startswith("/System/Library/"):
        return True
    plist = app / "Contents" / "Info.plist"
    if plist.exists():
        try:
            with plist.open("rb") as f:
                data = plistlib.load(f)
            bundle_id = data.get("CFBundleIdentifier")
            if isinstance(bundle_id, str) and bundle_id.casefold().startswith("com.apple."):
                return True
        except Exception:
            pass
    return False

def installed(process, executables=None):
    process = resolve_process(process, executables or {})
    if not isinstance(process, str) or not process.strip() or process == "any":
        return False
    bundle_path = bundle(process, executables)
    path = bundle_path or Path(process)
    return path.exists() if bundle_path else path.is_absolute() and path.exists()

def via_exists(via):
    if not isinstance(via, str):
        return True
    via = via.strip()
    if not via or via == "any":
        return True
    if via.startswith("path."):
        via = "/" + via[len("path."):]
    else:
        via = str(Path(via).expanduser())
    return bool(glob.glob(via))

def identifier_namespace(process):
    if not isinstance(process, str) or not process.startswith("identifier."):
        return None
    identifier = process[len("identifier."):]
    namespace = identifier.split("/", 1)[0].strip()
    return namespace or None

def identity(process, include_all, executables=None):
    if not include_all and is_apple_identifier(process):
        return None
    resolved = resolve_process(process, executables or {})
    p = resolved.lower() if isinstance(resolved, str) else ""
    if any(x in p for x in ("/opt/homebrew/", "/usr/local/opt/", "/usr/local/bin/", "/homebrew/")) and ".app/" not in p:
        return "homebrew", "Homebrew"
    if not include_all and is_apple_app(resolved, executables):
        return None

    # Identifier-based rules and path-based rules for the same application
    # must land in the same output file.  Prefer the resolved .app identity;
    # only use the code-signing namespace when no application bundle exists.
    name = app_name(resolved, executables)
    if name and bundle(resolved, executables):
        return app_key(name), name

    namespace = identifier_namespace(process)
    if namespace and name:
        return f"identifier.{namespace.casefold()}", name
    if name:
        return app_key(name), name
    if include_all and isinstance(process, str) and process not in {"", "any"}:
        return "macos", "macOS"
    return None

def description(name, rules):
    for rule in rules:
        b = bundle(rule.get("process"))
        if not b:
            continue
        plist = b / "Contents" / "Info.plist"
        if not plist.exists():
            continue
        try:
            with plist.open("rb") as f:
                data = plistlib.load(f)
        except Exception:
            continue
        for key in ("CFBundleGetInfoString", "NSHumanReadableDescription"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return f"Rules for {name} - {re.sub(r'\s+', ' ', value.strip()).rstrip('.')}."
    return f"Rules for {name} - network access rules for {name}."

def load_repository(directory):
    if not directory.is_dir():
        die(f"rules directory does not exist: {directory}")
    repo, process_files = {}, {}
    for path in sorted(directory.glob("*.lsrules")):
        if path.name.lower() == AGGREGATE_FILE:
            continue
        data = load_json(path)
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            die(f"{path}: invalid .lsrules file")
        key = app_key(path.stem)
        repo.setdefault(key, data)
        for rule in data["rules"]:
            if isinstance(rule, dict) and isinstance(rule.get("process"), str):
                process_files.setdefault(rule["process"], key)
    return repo, process_files

def group_name(group_id, groups):
    meta = groups.get(group_id, {})
    if isinstance(meta, dict):
        for key in ("userProvidedName", "name", "displayName", "title", "factoryName"):
            if isinstance(meta.get(key), str) and meta[key].strip():
                return meta[key].strip()
        return {"builtinICloudServices": "iCloud Services", "builtinMacOSServices": "macOS Services"}.get(meta.get("type"), group_id)
    return group_id

def excluded_groups(groups, include_all):
    if include_all:
        return set()
    excluded = set()
    for gid, meta in groups.items():
        if not isinstance(meta, dict):
            continue
        if meta.get("type") in EXCLUDED_TYPES:
            excluded.add(gid)
        elif APPLE_MARKER in str(meta.get("userProvidedDescription", "")).casefold() or str(meta.get("factoryName", "")).casefold() == "apple apps":
            excluded.add(gid)
    return excluded

def cutoff():
    now = datetime.now(timezone.utc)
    year, month = now.year, now.month - UNUSED_MONTHS
    while month <= 0:
        year, month = year - 1, month + 12
    return now.replace(year=year, month=month, day=min(now.day, calendar.monthrange(year, month)[1]))

def last_used(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        value = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    except ValueError:
        return None

def extract_model(path, include_all):
    data = load_json(path)
    groups, rules = data.get("groups"), data.get("rules")
    executables = data.get("lastSeenExecutableByCodeIdentifier", {})
    if not isinstance(executables, dict):
        executables = {}
    if not isinstance(groups, dict) or not isinstance(rules, list):
        die("Little Snitch export-model must contain top-level 'groups' and 'rules'")
    excluded = excluded_groups(groups, include_all)
    for gid in sorted(excluded):
        print(f"[+] Excluding Little Snitch group: {group_name(gid, groups)}")
    cutoff_date = cutoff()
    grouped, names = defaultdict(list), {}
    excluded_counts = defaultdict(int)
    unused_count = 0
    filtered_count = 0
    for raw in rules:
        if not isinstance(raw, dict):
            continue
        gid = str(raw["group"]) if raw.get("group") is not None else None
        if gid in excluded:
            excluded_counts[gid] += 1
            continue
        used = last_used(raw.get("lastUsed"))
        if used and used < cutoff_date:
            unused_count += 1
            continue
        filtered_count += 1
        rule = clean_rule(raw)
        process = rule.get("process")
        if not isinstance(process, str) or not process.strip():
            continue
        if not include_all and not installed(process, executables):
            continue
        if not include_all and not via_exists(rule.get("via")):
            continue
        item = identity(process, include_all, executables)
        if not item:
            continue
        key, name = item
        grouped[key].append(rule)
        names[key] = name
    for gid in sorted(excluded):
        print(f"[+] Excluded {excluded_counts[gid]} rule(s) from {group_name(gid, groups)}")
    print(f"[+] Excluded {unused_count} rule(s) unused for more than {UNUSED_MONTHS} month(s)")
    print(f"[+] Current rules after filtering: {filtered_count}")
    print(f"[+] Resolved {len(grouped)} application group(s) from current rules")
    return [(key, names[key], rules) for key, rules in grouped.items()]

def merge_repository_groups(current, process_files):
    # Existing files provide grouping hints only; their rules are never copied.
    parent = {key: key for key, _, _ in current}
    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[b] = a
    files = defaultdict(list)
    for key, _, rules in current:
        for rule in rules:
            repo_key = process_files.get(rule.get("process"))
            if repo_key:
                files[repo_key].append(key)
    for keys in files.values():
        for key in keys[1:]:
            union(keys[0], key)
    grouped = defaultdict(list)
    for item in current:
        grouped[find(item[0])].append(item)
    return [(items[0][0], items[0][1], [r for _, _, rules in items for r in rules]) for items in grouped.values()]

def metadata(name, rules, repo, process_files):
    keys = []
    for rule in rules:
        key = process_files.get(rule.get("process"))
        if key and key not in keys:
            keys.append(key)
    key = app_key(name)
    if key in repo and key not in keys:
        keys.append(key)
    if not keys:
        return None, None, None
    data = repo[keys[0]]
    return data.get("name"), data.get("description"), keys[0]

def filename(key, name, repo):
    if key == "homebrew":
        return "brew.lsrules"
    if key == "macos":
        return "macos.lsrules"
    if key in repo:
        return f"{key}.lsrules"
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-").lower()
    return f"{safe or key}.lsrules"

def build(key, name, rules, old_name, old_description):
    name = old_name or name
    if not old_description:
        old_description = {
            "homebrew": "Rules for Homebrew - network access rules for Homebrew formulae.",
            "macos": "Rules for macOS - network access rules for macOS system processes and services.",
        }.get(key, description(name, rules))
    return {"name": name, "description": old_description, "rules": canonicalize(rules)}

def export_model():
    temp = tempfile.NamedTemporaryFile(prefix="little-snitch-", suffix=".json", delete=False)
    path = Path(temp.name)
    temp.close()
    try:
        with path.open("w", encoding="utf-8") as f:
            proc = subprocess.run(["sudo", "littlesnitch", "export-model"], stdout=f, stderr=subprocess.PIPE, text=True)
        if proc.returncode:
            die(f"Little Snitch export failed: {proc.stderr.strip()}")
        return path
    except FileNotFoundError:
        die("Could not run Little Snitch export command")

def clean_output(directory):
    if directory.exists():
        for path in directory.glob("*.lsrules"):
            if path.name.lower() != AGGREGATE_FILE:
                path.unlink()

def merge_all(generated):
    return {
        "name": "Little Snitch Rules",
        "description": "Complete rule set from https://github.com/ucomesdag/little-snitch-rules",
        "rules": [rule for _, data in generated for rule in data["rules"]],
    }

def regenerate_all(directory):
    rules = []
    for path in sorted(directory.glob("*.lsrules")):
        if path.name == AGGREGATE_FILE:
            continue
        data = load_json(path)
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            die(f"{path}: invalid .lsrules file")
        rules.extend(data["rules"])
    return {
        "name": "Little Snitch Rules",
        "description": "Complete rule set from https://github.com/ucomesdag/little-snitch-rules",
        "rules": rules,
    }

def main():
    parser = argparse.ArgumentParser(description="Generate normalized Little Snitch .lsrules files.")
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--include-all", action="store_true", help="include all groups and uninstalled applications")
    parser.add_argument("--regenerate-all", action="store_true", help="regenerate all.lsrules from --output-dir without exporting rules")
    args = parser.parse_args()

    if args.regenerate_all:
        destination = args.output_dir
        destination.mkdir(parents=True, exist_ok=True)
        aggregate = destination / AGGREGATE_FILE
        data = regenerate_all(destination)
        if args.dry_run:
            print(f"would write {aggregate} ({len(data['rules'])} rules)")
        else:
            write_json(aggregate, data)
            print(f"wrote {aggregate} ({len(data['rules'])} rules)")
        return 0
    print(f"[+] Reading existing rules from {args.rules_dir}")
    repo, process_files = load_repository(args.rules_dir)
    print(f"[+] Found {len(repo)} existing .lsrules file(s)")
    export = export_model()
    try:
        print(f"[+] Parsing Little Snitch export: {export}")
        current = merge_repository_groups(extract_model(export, args.include_all), process_files)
        destination = args.output_dir
        if not args.dry_run:
            destination.mkdir(parents=True, exist_ok=True)
            clean_output(destination)
        generated = []
        for key, name, rules in sorted(current, key=lambda x: x[1].casefold()):
            old_name, old_description, old_key = metadata(name, rules, repo, process_files)
            output_key = old_key or key
            data = build(output_key, name, rules, old_name, old_description)
            path = destination / filename(output_key, data["name"], repo)
            generated.append((path, data))
            print(f"[+] {data['name']}: {len(rules)} current rule(s) -> {len(data['rules'])} normalized rule(s)")
        aggregate = destination / AGGREGATE_FILE
        if args.dry_run:
            all_data = {
                "name": "Little Snitch Rules",
                "description": "Complete rule set from https://github.com/ucomesdag/little-snitch-rules",
                "rules": [],
            }
            print("would generate all.lsrules from the individual generated files")
            for path, data in generated:
                print(f"would write {path} ({len(data['rules'])} rules)")
            print(f"would write {aggregate} ({len(all_data['rules'])} rules)")
            return 0
        for path, data in generated:
            write_json(path, data)
            print(f"wrote {path} ({len(data['rules'])} rules)")

        # Build all.lsrules from the files that were actually written.
        all_data = regenerate_all(destination)
        write_json(aggregate, all_data)
        print(f"wrote {aggregate} ({len(all_data['rules'])} rules)")
        print(f"\nDone. Generated {len(generated)} rule file(s) in {destination}")
        return 0
    finally:
        export.unlink(missing_ok=True)
if __name__ == "__main__":
    raise SystemExit(main())
