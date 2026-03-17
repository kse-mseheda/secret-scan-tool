# Lab: Custom Secret Detection Tool

## Objective

Analyze and understand the source code of a custom secret detection tool. Create a reusable GitHub Actions workflow for building and pushing Docker images to GitHub Container Registry (GHCR), publish it in `kse-labs-trusted-workflows`, and integrate secret scanning and Docker CI into your microservices repositories.

---

## Prerequisites

Before pushing code that contains test secrets (e.g., `test_secrets.txt`, `tests/test_e2e.py`), you must disable GitHub's built-in **push protection** at the organization level. Otherwise GitHub will reject the push with `GH013: Repository rule violations`.

1. **Disable at organization level:** Go to **https://github.com/organizations/\<your-org\>/settings/security_products** and disable **Secret scanning** → **Push protection**.
2. **Disable at repository level:** Go to **https://github.com/\<your-org\>/\<repo-name\>/settings/security_analysis** and disable **Secret scanning** for the repository.
3. Push the code.
4. After pushing, re-enable both settings (repository and organization level).

> **Important:** Both levels must be disabled. The organization policy can enforce secret scanning on all repositories, and the repository-level setting can independently block pushes. GitHub's push protection scans content *before* it lands in the repository, so `.github/secret_scanning.yml` path exclusions do not apply during push — they only suppress alerts after code is already in the repo.

---

## Part 1: Source Code Analysis

### 1.1 Project Structure

Review the project layout and understand the role of each file:

```
custom-secret-detect/
├── secret_detect.py      # Main detection engine
├── rules.json            # Detection rules (regex patterns, entropy thresholds)
├── config.json           # Allowlisted paths and stopwords
├── Dockerfile            # Container packaging
├── scan.sh               # CI helper script
├── test_secrets.txt      # Sample file with embedded secrets for testing
├── tests/
│   ├── test_unit.py      # Unit tests for core functions
│   └── test_e2e.py       # End-to-end tests (CLI behavior)
└── docs/
    └── how-it-works.md   # Technical documentation
```

### 1.2 Detection Engine (`secret_detect.py`)

Analyze the scanning pipeline by reading through each stage:

1. **`load_rules()`** — Loads detection rules from `rules.json`. Each rule defines a regex pattern, keyword pre-filters, and optional entropy thresholds.

2. **`load_config()`** — Loads allowlisted paths and stopwords from `config.json`.

3. **`scan_directory()` / `scan_file()`** — File discovery. Recursively walks directories, skipping hidden dirs and common non-code directories (`.git`, `node_modules`, `vendor`, `__pycache__`).

4. **`is_allowlisted_path()`** — Checks file paths against patterns in `config.json`. Files matching patterns like `*.min.js`, `package-lock.json`, or binary extensions are skipped entirely.

5. **`scan_line()`** — The core detection logic for a single line:
   - **Keyword pre-filter**: Checks if any rule keywords appear in the line before running the regex (performance optimization).
   - **Regex matching**: Applies `re.finditer()` with the rule's pattern. Uses `secret_group` to extract the relevant capture group.
   - **Shannon entropy filtering**: Computes the randomness of the matched string. Matches below the rule's entropy threshold are discarded as likely false positives.
   - **False-positive filtering**: Discards matches containing stopwords (`example`, `test`, `fake`, etc.) or with 2 or fewer unique characters.

6. **`shannon_entropy()`** — Calculates information density using the formula `H = -sum(p(c) * log2(p(c)))`. Higher values mean more randomness, indicating a likely real secret.

7. **Baseline support** — `load_baseline()` and `filter_baseline()` allow suppressing known findings by matching on `(rule_id, file, line)`.

### 1.3 Rules (`rules.json`)

Examine each rule and understand its fields:

| Field          | Purpose                                                        |
|----------------|----------------------------------------------------------------|
| `id`           | Unique identifier for the rule                                 |
| `description`  | Human-readable name                                            |
| `regex`        | Pattern to match the secret                                    |
| `keywords`     | Fast pre-filter strings (checked before regex)                 |
| `entropy`      | Minimum Shannon entropy threshold (optional)                   |
| `secret_group` | Which regex capture group contains the actual secret (optional)|

Questions to answer:
- Why do some rules have an `entropy` threshold and others don't?
- What is the purpose of `secret_group` and which rules use it?
- How does the keyword pre-filter improve performance?

### 1.4 Configuration (`config.json`)

Review the two sections:
- **`allowlist_paths`** — Regex patterns for file paths to skip. Why are lock files and binary formats excluded?
- **`allowlist_stopwords`** — Strings that indicate a match is not a real secret. Why is `"test"` in this list?

### 1.5 Tests

Read through both test files and understand the testing strategy:
- **`tests/test_unit.py`** — Tests individual functions (`shannon_entropy`, `is_allowlisted_path`, `is_false_positive`, `scan_line`). Note how entropy filtering is tested with both low and high entropy inputs for each rule.
- **`tests/test_e2e.py`** — Tests the full CLI by running `secret_detect.py` as a subprocess. Covers detection, clean files, directory scanning, recursive scanning, and CLI options including baseline support.

Run the tests and verify all pass:
```bash
./venv/bin/python -m pytest tests/ -v
```

### 1.6 CLI Options

Review the argument parser in `main()` and understand each flag:

```
python secret_detect.py <path> [--rules FILE] [--config FILE] [--json] [--exit-code N] [--baseline FILE] [--create-baseline FILE]
```

| Argument            | Description                                              |
|---------------------|----------------------------------------------------------|
| `path`              | File or directory to scan                                |
| `--rules`           | Custom rules JSON file (overrides default `rules.json`)  |
| `--config`          | Custom config JSON file (overrides default `config.json`)|
| `--json`            | Output findings as JSON                                  |
| `--exit-code`       | Exit code when secrets are found (default: `1`)          |
| `--baseline`        | Baseline JSON file of known findings to suppress         |
| `--create-baseline` | Write current findings to a file for future suppression  |

---

## Part 2: Build and Push to GitHub Container Registry

The `kse-labs-trusted-workflows` repository already contains a reusable workflow `docker-build.yaml` for building and pushing Docker images to GHCR. In this part you will call that workflow from this repository to automatically build and publish the secret detection tool.

### 2.1 Analyze the Existing Reusable Workflow

Review `docker-build.yaml` in the `kse-labs-trusted-workflows` repository. It accepts the following inputs:

| Input         | Required | Default        | Description                                |
|---------------|----------|----------------|--------------------------------------------|
| `image-name`  | Yes      | —              | Image name without registry prefix         |
| `context`     | No       | `.`            | Docker build context path                  |
| `dockerfile`  | No       | `Dockerfile`   | Path to Dockerfile (relative to context)   |
| `tags`        | No       | `latest`       | Comma-separated image tags                 |
| `push`        | No       | `false`        | Whether to push the image to the registry  |
| `registry`    | No       | `ghcr.io`      | Container registry                         |
| `platforms`   | No       | `linux/amd64`  | Target platforms                           |

Key details:
- Runs on `self-hosted` runners.
- Uses Docker Buildx with GitHub Actions cache (`cache-from`/`cache-to: type=gha`).
- Only logs in to the registry when `push` is `true`.
- Tags are built as `<registry>/<repo-owner>/<image-name>:<tag>` for each comma-separated tag.

Questions to answer:
- What is `workflow_call` and how is it different from `workflow_dispatch`?
- Why does the job need `packages: write` permission?
- Why does the workflow only log in to the registry when `push` is `true`?
- What is the benefit of GHA cache (`cache-from`/`cache-to: type=gha`)?

### 2.2 Analyze the Dockerfile

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY secret_detect.py rules.json config.json ./
ENTRYPOINT ["python", "secret_detect.py"]
CMD ["--help"]
```

Questions to answer:
- Why is `python:3.12-slim` used instead of the full image?
- What is the difference between `ENTRYPOINT` and `CMD` here?
- How does volume mounting (`-v`) allow scanning files outside the container?

---

## Part 3: CI/CD Integration

### 3.1 Reference: `my-app` CI Example

Before writing your own workflow, study the existing example at `kse-bd8338bbe006/my-app`. Its `ci-main.yml` follows this pattern:

1. **`build-and-test`** — Checks out code, installs dependencies, runs tests.
2. **`docker-build-push`** — Runs on `self-hosted`, logs in to GHCR, builds and pushes the image tagged with the commit SHA (`ghcr.io/<repo>:<sha>`).
3. **`update-deployment`** — Checks out the `kse-labs-deployment` repo, updates the image tag in the deployment manifest, commits and pushes.

Note that this example builds Docker inline (not via the reusable workflow). You can choose either approach — use the reusable `docker-build.yaml` or build inline as `my-app` does.

### 3.2 Add CI to `custom-secret-detect`

Create `.github/workflows/ci.yml` for this repository. Two approaches are shown:

**Option A: Using the reusable workflow**

```yaml
name: CI

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install pytest
      - name: Run tests
        run: python -m pytest tests/ -v

  docker:
    needs: test
    uses: <your-org>/kse-labs-trusted-workflows/.github/workflows/docker-build.yaml@main
    with:
      image-name: custom-secret-detect
      push: true
      tags: "${{ github.sha }},latest"
    permissions:
      contents: read
      packages: write
```

**Option B: Inline build (same pattern as `my-app`)**

```yaml
name: CI

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install dependencies
        run: pip install pytest
      - name: Run tests
        run: python -m pytest tests/ -v

  docker-build-push:
    needs: test
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### 3.3 Add CI to Your Microservices Repositories

For each microservice repository, create a CI workflow that builds, pushes, and runs secret scanning. Follow the same pattern — adapt the test job to your language/framework:

```yaml
name: CI

on:
  push:
    branches: [main]

permissions:
  contents: read
  packages: write

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ... service-specific test steps (go test, npm test, mvn test, etc.) ...

  docker-build-push:
    needs: test
    runs-on: self-hosted
    steps:
      - uses: actions/checkout@v4

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Pull secret scanner
        run: docker pull ghcr.io/<your-org>/custom-secret-detect:latest
      - name: Run secret scan
        run: |
          docker run --rm \
            -v "${{ github.workspace }}":/scan \
            ghcr.io/<your-org>/custom-secret-detect:latest \
            /scan/
```

### 3.4 Verification Checklist

For each repository, verify:
- [ ] Push to `main` triggers the workflow.
- [ ] Tests run and pass before the Docker build.
- [ ] Docker image is built and pushed to `ghcr.io/<your-org>/<image-name>:<sha>`.
- [ ] The image is visible at `https://github.com/orgs/<your-org>/packages`.
- [ ] Secret scan step detects secrets and fails the pipeline if found.

---

## Part 4: Git History Sanitization

### Scenario

A credential was accidentally committed to the repository and needs to be removed from the entire Git history.

### Tasks

1. **Simulate an accidental commit**
   ```bash
   echo "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > credentials.env
   git add credentials.env
   git commit -m "add config"
   ```

2. **Remove the file from Git history using `git filter-repo`**
   ```bash
   pip install git-filter-repo
   git filter-repo --path credentials.env --invert-paths
   ```

3. **Alternative: Use BFG Repo Cleaner**
   ```bash
   bfg --delete-files credentials.env

   echo "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" > passwords.txt
   bfg --replace-text passwords.txt

   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   ```

4. **Verify the cleanup**
   ```bash
   git log --all -p | grep -c "wJalrXUtnFEMI"
   python secret_detect.py .
   ```

5. **Force push the cleaned history** (coordinate with team)
   ```bash
   git push origin --force --all
   ```

6. **Post-cleanup checklist**
   - Rotate the exposed credential immediately — removing it from Git history does not revoke it.
   - Notify team members to re-clone the repository after a force push.
   - Add the file pattern to `.gitignore`:
     ```
     *.env
     credentials*
     ```

---

## Bonus: Multithreaded Scanning (+2 points)

Implement multithreaded file scanning using the **producer/consumer** pattern:

- **Producer**: walks the directory tree and places file paths into a shared queue.
- **Consumers**: a pool of worker threads that pull file paths from the queue and scan each file for secrets.

Requirements:
- Use `threading` and `queue.Queue` from the Python standard library.
- The number of worker threads should be configurable via a `--threads N` CLI argument (default: 4).
- Results must be collected thread-safely and output must remain identical to the single-threaded version.
- Add tests verifying that multithreaded scanning produces the same findings as single-threaded scanning.

---

## Deliverables

- [ ] Written answers to the analysis questions in Parts 1 and 2.
- [ ] `custom-secret-detect` Docker image automatically built and pushed to GHCR via `docker-build.yaml`.
- [ ] At least one microservice repository reusing `docker-build.yaml` for Docker build/push and running secret scanning in CI.
- [ ] Demonstration of Git history sanitization with verification.
- [ ] *(Bonus, +2 points)* Multithreaded scanning with producer/consumer pattern and tests.
