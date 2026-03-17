# How Secret Detection Works

`secret_detect.py` is a standalone secret detection tool that scans files and directories for hardcoded secrets such as API keys, tokens, and private keys.

## Architecture Overview

The tool follows a pipeline approach: **file discovery → line scanning → keyword pre-filter → regex matching → entropy filtering → false-positive checks → reporting**.

## Rules

Each detection rule is a dictionary with the following fields:

| Field          | Required | Description                                                                 |
|----------------|----------|-----------------------------------------------------------------------------|
| `id`           | Yes      | Unique identifier for the rule (e.g., `aws-access-token`)                  |
| `description`  | Yes      | Human-readable name of the secret type                                     |
| `regex`        | Yes      | Regular expression pattern to match the secret                             |
| `keywords`     | Yes      | List of strings used for fast pre-filtering before applying the regex      |
| `entropy`      | No       | Minimum Shannon entropy threshold; matches below this are discarded        |
| `secret_group` | No       | Regex capture group index to extract the secret from (defaults to `0`)     |

### Supported Secret Types

- AWS Access Key IDs
- GitHub Personal Access Tokens, OAuth tokens, and fine-grained PATs
- GitLab Personal Access Tokens
- Slack Bot Tokens and Webhook URLs
- Stripe Secret Keys
- Private Keys (RSA, EC, DSA, OpenSSH, PGP)
- Google API Keys
- Heroku API Keys
- Twilio API Keys
- JSON Web Tokens (JWT)
- Generic API keys/secrets (broad pattern with higher entropy threshold)

## Scanning Pipeline

### 1. File Discovery

`scan_directory()` recursively walks the target path using `os.walk()`. It skips hidden directories and common non-code directories (`node_modules`, `vendor`, `__pycache__`, `.git`).

### 2. Path Allowlisting

Before scanning a file, `is_allowlisted_path()` checks the file path against a list of patterns. Files matching any of the following are skipped entirely:

- `.git/`, `node_modules/`, `vendor/`
- Minified JS files (`*.min.js`)
- Lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.sum`)
- Binary/media files (images, fonts, PDFs, archives, executables)

### 3. Keyword Pre-filter

For each line, the scanner checks whether any of the rule's `keywords` appear in the line (case-insensitive). If none match, the rule's regex is skipped entirely. This is a performance optimization -- regex evaluation is expensive, and most lines won't contain secrets.

### 4. Regex Matching

If keywords match, the rule's `regex` is applied to the line using `re.finditer()`. The secret value is extracted from the capture group specified by `secret_group` (defaulting to group `0`, the full match).

### 5. Shannon Entropy Filtering

For rules that define an `entropy` threshold, the Shannon entropy of the matched secret is calculated. Shannon entropy measures the randomness/information density of a string using the formula:

```
H = -sum(p(c) * log2(p(c))) for each unique character c
```

Where `p(c)` is the frequency of character `c` divided by the string length.

Entropy values by example:

| String          | Unique chars | Entropy | Interpretation          |
|-----------------|--------------|---------|-------------------------|
| `aaaaaaa`       | 1            | 0.0     | Completely predictable  |
| `aaaaaab`       | 2            | ~0.59   | Mostly predictable      |
| `aabbccdd`      | 4            | 2.0     | Moderate randomness     |
| `abcdefghij`    | 10           | ~3.32   | High randomness         |

The more unique characters a string has, and the more evenly they are distributed, the higher the entropy. The theoretical maximum for a string is `log2(unique_characters)` — for example, a string using all 26 uppercase letters equally would max out at `log2(26) ≈ 4.7`.

If the entropy falls below the rule's threshold, the match is discarded as a likely false positive. Rules with highly specific prefixes (e.g., `ghp_`, `glpat-`) don't need entropy checks because the prefix alone is strong evidence.

The thresholds used:

| Rule              | Threshold | Rationale                                              |
|-------------------|-----------|--------------------------------------------------------|
| `aws-access-token`| 3.0       | Prefix (`AKIA`, etc.) is only 4 chars; rest must look random |
| `generic-api-key` | 3.5       | Very broad regex; higher bar to reduce noise           |
| `twilio-api-key`  | 3.0       | `SK` prefix is common in non-secret contexts           |

#### Example: Why AWS Needs Entropy Filtering

The AWS regex `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b` matches any 20-character string starting with a valid AWS prefix. Without entropy filtering, it would match obvious non-secrets like documentation examples and placeholders. The `3.0` threshold separates these from real keys:

| String                 | Entropy | Result   |
|------------------------|---------|----------|
| `AKIAAAAAAAAAAAAAAAAA` | ~0.9    | Rejected |
| `AKIAABCABCABCABCABCA` | ~2.1    | Rejected |
| `AKIAIOSFODNN7EXAMPLE` | ~3.7    | Accepted |
| `AKIA3FG8HJWE9RKDQ5XN` | ~4.0   | Accepted |

Real AWS keys are randomly generated and have high character diversity, so they comfortably clear the `3.0` threshold. Placeholders and repetitive patterns fall below it and are discarded.

### 6. False-Positive Filtering

`is_false_positive()` applies additional heuristics to discard matches that are clearly not real secrets:

- **Stopwords**: Matches containing words like `example`, `test`, `fake`, `sample`, `placeholder`, `XXXX`, `0000`, or `1234` are discarded.
- **Low uniqueness**: Matches with 2 or fewer distinct characters are discarded (e.g., `AAABBBAAABBB`).

## Output

The tool supports two output formats:

- **Text** (default): Color-coded terminal output showing the rule ID, file path, line number, description, matched value (truncated to 60 characters), and entropy.
- **JSON** (`--json`): Machine-readable array of finding objects.

## CLI Usage

```
python secret_detect.py <path> [--json] [--exit-code N] [--baseline FILE] [--create-baseline FILE]
```

| Argument              | Description                                            |
|-----------------------|--------------------------------------------------------|
| `path`                | File or directory to scan                              |
| `--json`              | Output findings as JSON                                |
| `--exit-code`         | Exit code when secrets are found (default: `1`)        |
| `--baseline`          | Path to a baseline JSON file of known findings to ignore |
| `--create-baseline`   | Write current findings to a baseline JSON file and exit |

The tool exits with `0` if no secrets are found, or with the configured exit code (default `1`) if any are detected.

## Baseline / Allowlist Support

The baseline feature allows you to suppress known false positives or accepted findings so they don't fail your CI pipeline.

### Creating a Baseline

Run the scanner with `--create-baseline` to capture all current findings into a JSON file:

```bash
python secret_detect.py . --create-baseline .secret-baseline.json
```

This writes every finding as a JSON array and exits with code `0`. Each entry contains the `rule_id`, `file`, and `line` that uniquely identify the finding.

### Using a Baseline

Pass the baseline file with `--baseline` on subsequent scans:

```bash
python secret_detect.py . --baseline .secret-baseline.json
```

Findings that match an entry in the baseline by `(rule_id, file, line)` are suppressed. New secrets not in the baseline still trigger a non-zero exit code. The number of suppressed findings is printed to stderr.

If the baseline file does not exist, the scan proceeds normally without error.

### Workflow

1. Run an initial scan and review all findings
2. Create a baseline for accepted/false-positive findings
3. Commit `.secret-baseline.json` to the repository
4. CI runs with `--baseline` — only new secrets fail the build
5. Periodically re-review and update the baseline as code changes

## CI Integration

The included `scan.sh` script builds the Docker image and runs the scanner with volume mounting:

```bash
# Scan the entire project
./scan.sh

# Scan a specific path
./scan.sh src/

# With baseline (auto-detected if .secret-baseline.json exists)
./scan.sh
```

### Exit Codes

| Code | Meaning                        |
|------|--------------------------------|
| `0`  | No secrets found               |
| `1`  | Secrets detected (default, configurable via `--exit-code`) |
| `2`  | Invalid path or runtime error  |

In a CI pipeline, the non-zero exit code will fail the build step when new secrets are introduced.
