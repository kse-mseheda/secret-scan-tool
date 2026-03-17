#!/usr/bin/env python3
"""Simple secret detection tool inspired by gitleaks."""

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
from dataclasses import dataclass, asdict

# --- Rules ---

DEFAULT_RULES_PATH = Path(__file__).parent / "rules.json"
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.json"


def load_rules(rules_path: str | Path | None = None) -> list[dict]:
    """Load rules from a JSON configuration file."""
    path = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
    with open(path) as f:
        rules = json.load(f)
    for rule in rules:
        if "id" not in rule or "regex" not in rule:
            raise ValueError(f"Rule missing required 'id' or 'regex' field: {rule}")
    return rules


def load_config(config_path: str | Path | None = None) -> dict:
    """Load configuration from a JSON file."""
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
    with open(path) as f:
        return json.load(f)


# --- Allowlist ---


# --- Core ---

@dataclass
class Finding:
    rule_id: str
    description: str
    file: str
    line: int
    match: str
    entropy: float


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def is_allowlisted_path(filepath: str, allowlist_paths: list[str]) -> bool:
    for pattern in allowlist_paths:
        if re.search(pattern, filepath):
            return True
    return False


def is_false_positive(secret: str, allowlist_stopwords: list[str]) -> bool:
    for word in allowlist_stopwords:
        if word in secret:
            return True
    # All same characters
    if len(set(secret)) <= 2:
        return True
    return False


def scan_line(line: str, rules: list[dict], stopwords: list[str]) -> list[tuple[dict, str, float]]:
    """Scan a single line against all rules. Returns list of (rule, match, entropy)."""
    results = []
    line_lower = line.lower()

    for rule in rules:
        # Keyword pre-filter
        keywords = rule.get("keywords", [])
        if keywords and not any(kw.lower() in line_lower for kw in keywords):
            continue

        for m in re.finditer(rule["regex"], line):
            secret_group = rule.get("secret_group", 0)
            try:
                secret = m.group(secret_group)
            except IndexError:
                secret = m.group(0)

            ent = shannon_entropy(secret)

            min_entropy = rule.get("entropy", 0)
            if min_entropy and ent < min_entropy:
                continue

            if is_false_positive(secret, stopwords):
                continue

            # Truncate display match
            display = secret if len(secret) <= 60 else secret[:30] + "..." + secret[-10:]
            results.append((rule, display, round(ent, 2)))

    return results


def scan_file(filepath: str, rules: list[dict], config: dict) -> list[Finding]:
    """Scan a single file for secrets."""
    if is_allowlisted_path(filepath, config["allowlist_paths"]):
        return []

    findings = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for rule, match, ent in scan_line(line, rules, config["allowlist_stopwords"]):
                    findings.append(Finding(
                        rule_id=rule["id"],
                        description=rule["description"],
                        file=filepath,
                        line=line_num,
                        match=match,
                        entropy=ent,
                    ))
    except (OSError, UnicodeDecodeError):
        pass
    return findings


SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__"}


def scan_directory(path: str, rules: list[dict], config: dict) -> list[Finding]:
    """Recursively scan a directory for secrets."""
    findings = []
    for filepath in Path(path).rglob("*"):
        if filepath.is_file() and not any(part.startswith(".") or part in SKIP_DIRS for part in filepath.parts):
            findings.extend(scan_file(str(filepath), rules, config))
    return findings


# --- Output ---

def load_baseline(path: str) -> set[tuple[str, str, int]]:
    """Load a baseline JSON file. Returns a set of (rule_id, file, line) tuples to ignore."""
    try:
        with open(path) as f:
            entries = json.load(f)
        return {(e["rule_id"], e["file"], e["line"]) for e in entries}
    except FileNotFoundError:
        return set()


def filter_baseline(findings: list[Finding], baseline: set[tuple[str, str, int]]) -> list[Finding]:
    """Remove findings that match the baseline."""
    return [f for f in findings if (f.rule_id, f.file, f.line) not in baseline]


def print_text(findings: list[Finding]) -> None:
    for f in findings:
        print(f"\033[91m[{f.rule_id}]\033[0m {f.file}:{f.line}")
        print(f"  {f.description}")
        print(f"  Match: {f.match} (entropy: {f.entropy})")
        print()


def print_json(findings: list[Finding]) -> None:
    print(json.dumps([asdict(f) for f in findings], indent=2))


# --- CLI ---

def main():
    parser = argparse.ArgumentParser(
        description="Simple secret detection tool (inspired by gitleaks)"
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--rules", default=None,
                        help=f"Path to rules JSON file (default: {DEFAULT_RULES_PATH})")
    parser.add_argument("--config", default=None,
                        help=f"Path to config JSON file (default: {DEFAULT_CONFIG_PATH})")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--exit-code", type=int, default=1,
                        help="Exit code when secrets are found (default: 1)")
    parser.add_argument("--baseline", default=None,
                        help="Path to baseline JSON file of known findings to ignore")
    parser.add_argument("--create-baseline", default=None,
                        help="Write current findings to a baseline JSON file and exit")
    args = parser.parse_args()

    rules = load_rules(args.rules)
    config = load_config(args.config)

    target = args.path
    if os.path.isfile(target):
        findings = scan_file(target, rules, config)
    elif os.path.isdir(target):
        findings = scan_directory(target, rules, config)
    else:
        print(f"Error: {target} not found", file=sys.stderr)
        sys.exit(2)

    if args.create_baseline:
        with open(args.create_baseline, "w") as f:
            json.dump([asdict(finding) for finding in findings], f, indent=2)
        print(f"Baseline created with {len(findings)} finding(s): {args.create_baseline}")
        sys.exit(0)

    if args.baseline:
        baseline = load_baseline(args.baseline)
        total = len(findings)
        findings = filter_baseline(findings, baseline)
        suppressed = total - len(findings)
        if suppressed:
            print(f"Suppressed {suppressed} baseline finding(s).\n", file=sys.stderr)

    if args.json:
        print_json(findings)
    else:
        if findings:
            print(f"Found {len(findings)} secret(s):\n")
            print_text(findings)
        else:
            print("No secrets found.")

    sys.exit(args.exit_code if findings else 0)


if __name__ == "__main__":
    main()
