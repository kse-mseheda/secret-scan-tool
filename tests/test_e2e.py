"""End-to-end tests: run secret_detect.py against files and verify detection."""
import subprocess
import sys
import os
import json
import tempfile

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "secret_detect.py")
PYTHON = sys.executable


def run_scan(*args):
    """Run secret_detect.py and return (returncode, stdout, stderr)."""
    result = subprocess.run(
        [PYTHON, SCRIPT, *args],
        capture_output=True, text=True,
    )
    return result.returncode, result.stdout, result.stderr


class TestE2EDetection:
    """Scan test_secrets.txt and verify real secrets are found."""

    def test_finds_secrets_in_test_file(self):
        test_file = os.path.join(os.path.dirname(SCRIPT), "test_secrets.txt")
        rc, stdout, _ = run_scan(test_file)
        assert rc == 1, f"Expected exit code 1, got {rc}"
        assert "secret(s)" in stdout

    def test_json_output(self):
        test_file = os.path.join(os.path.dirname(SCRIPT), "test_secrets.txt")
        rc, stdout, _ = run_scan(test_file, "--json")
        assert rc == 1
        findings = json.loads(stdout)
        assert isinstance(findings, list)
        assert len(findings) > 0
        rule_ids = {f["rule_id"] for f in findings}
        assert "aws-access-token" in rule_ids
        assert "private-key" in rule_ids

    def test_detects_aws_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("AWS_ACCESS_KEY_ID=AKIAZ7VRSQWB4XKHT5DO\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "aws-access-token" for f in findings)

    def test_detects_github_pat(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("GITHUB_TOKEN=ghp_R2D2C3POLukeSkywalkerHanSoloChewworx\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "github-pat" for f in findings)

    def test_detects_private_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "private-key" for f in findings)

    def test_detects_slack_webhook(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("WEBHOOK=https://hooks.slack.com/services/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\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "slack-webhook" for f in findings)

    def test_detects_stripe_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("STRIPE_SECRET=sk_live_AbCdEfGhIjKlMnOpQrStUvWx\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "stripe-secret-key" for f in findings)

    def test_detects_jwt(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("AUTH=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "jwt" for f in findings)

    def test_detects_google_api_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("GOOGLE_API_KEY=AIzaSyBnMpQrStUvWxYzHjKlTgRsDfGhJkLqWeR\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "google-api-key" for f in findings)

    def test_detects_generic_api_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write('api_key = "Abc123Def456Ghi789Jkl012Mno345"\n')
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert any(f["rule_id"] == "generic-api-key" for f in findings)


class TestE2ECleanFiles:
    """Verify clean files produce no findings."""

    def test_clean_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("print('hello world')\nx = 42\n")
            f.flush()
            rc, stdout, _ = run_scan(f.name)
        os.unlink(f.name)
        assert rc == 0
        assert "No secrets found" in stdout

    def test_false_positive_not_reported(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write('api_key = "EXAMPLE_KEY_PLACEHOLDER"\n')
            f.write('api_key = "aaaaaaaaaaaaaaaaaaaaaa"\n')
            f.flush()
            rc, stdout, _ = run_scan(f.name, "--json")
        os.unlink(f.name)
        findings = json.loads(stdout)
        assert findings == []
        assert rc == 0


class TestE2EDirectoryScan:
    """Test scanning a directory."""

    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # File with a secret
            with open(os.path.join(tmpdir, "config.py"), "w") as f:
                f.write("GITHUB_TOKEN=ghp_R2D2C3POLukeSkywalkerHanSoloChewworx\n")
            # Clean file
            with open(os.path.join(tmpdir, "main.py"), "w") as f:
                f.write("print('hello')\n")

            rc, stdout, _ = run_scan(tmpdir, "--json")
            findings = json.loads(stdout)
            assert rc == 1
            assert len(findings) >= 1
            assert any(f["rule_id"] == "github-pat" for f in findings)


class TestE2ERecursiveScan:
    """Test that directory scanning is truly recursive into nested subdirs."""

    def test_finds_secret_in_nested_subdir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = os.path.join(tmpdir, "a", "b", "c")
            os.makedirs(nested)
            with open(os.path.join(nested, "deep.txt"), "w") as f:
                f.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")

            rc, stdout, _ = run_scan(tmpdir, "--json")
            findings = json.loads(stdout)
            assert rc == 1
            assert any(f["rule_id"] == "aws-access-token" for f in findings)

    def test_finds_secrets_across_multiple_depths(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Secret at root level
            with open(os.path.join(tmpdir, "root.txt"), "w") as f:
                f.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")

            # Secret one level deep
            lvl1 = os.path.join(tmpdir, "level1")
            os.makedirs(lvl1)
            with open(os.path.join(lvl1, "mid.txt"), "w") as f:
                f.write("-----BEGIN RSA PRIVATE KEY-----\n")

            # Secret two levels deep
            lvl2 = os.path.join(tmpdir, "level1", "level2")
            os.makedirs(lvl2)
            with open(os.path.join(lvl2, "deep.txt"), "w") as f:
                f.write("token=sk_live_AbCdEfGhIjKlMnOpQrStUvWx\n")

            rc, stdout, _ = run_scan(tmpdir, "--json")
            findings = json.loads(stdout)
            rule_ids = {f["rule_id"] for f in findings}
            assert "aws-access-token" in rule_ids
            assert "private-key" in rule_ids
            assert "stripe-secret-key" in rule_ids

    def test_skips_hidden_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hidden = os.path.join(tmpdir, ".hidden")
            os.makedirs(hidden)
            with open(os.path.join(hidden, "secret.txt"), "w") as f:
                f.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")

            rc, stdout, _ = run_scan(tmpdir, "--json")
            findings = json.loads(stdout)
            assert findings == []
            assert rc == 0

    def test_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = os.path.join(tmpdir, "node_modules", "pkg")
            os.makedirs(nm)
            with open(os.path.join(nm, "config.js"), "w") as f:
                f.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")

            rc, stdout, _ = run_scan(tmpdir, "--json")
            findings = json.loads(stdout)
            assert findings == []
            assert rc == 0


class TestE2ECLIOptions:
    """Test CLI arguments."""

    def test_custom_exit_code(self):
        test_file = os.path.join(os.path.dirname(SCRIPT), "test_secrets.txt")
        rc, _, _ = run_scan(test_file, "--exit-code", "42")
        assert rc == 42

    def test_nonexistent_path(self):
        rc, _, stderr = run_scan("/nonexistent/path")
        assert rc == 2

    def test_exit_zero_on_clean(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("nothing here\n")
            f.flush()
            rc, _, _ = run_scan(f.name)
        os.unlink(f.name)
        assert rc == 0

    def test_custom_rules_file(self):
        custom_rules = [
            {"id": "custom-secret", "description": "Custom", "regex": "MYSECRET_[A-Z]{10,}"}
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as rf:
            json.dump(custom_rules, rf)
            rf.flush()
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
                sf.write("val=MYSECRET_ABCDEFGHIJKL\n")
                sf.flush()
                rc, stdout, _ = run_scan(sf.name, "--rules", rf.name, "--json")
        os.unlink(rf.name)
        os.unlink(sf.name)
        findings = json.loads(stdout)
        assert rc == 1
        assert any(f["rule_id"] == "custom-secret" for f in findings)

    def test_create_baseline(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
            sf.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")
            sf.flush()
            baseline_path = sf.name + ".baseline.json"
            rc, stdout, _ = run_scan(sf.name, "--create-baseline", baseline_path)
        assert rc == 0
        assert "Baseline created" in stdout
        with open(baseline_path) as f:
            baseline = json.load(f)
        assert len(baseline) > 0
        assert any(e["rule_id"] == "aws-access-token" for e in baseline)
        os.unlink(sf.name)
        os.unlink(baseline_path)

    def test_baseline_suppresses_known_findings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
            sf.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")
            sf.flush()
            # First create the baseline
            baseline_path = sf.name + ".baseline.json"
            run_scan(sf.name, "--create-baseline", baseline_path)
            # Now scan with baseline — should suppress all findings
            rc, stdout, stderr = run_scan(sf.name, "--baseline", baseline_path, "--json")
        findings = json.loads(stdout)
        assert rc == 0
        assert findings == []
        assert "Suppressed" in stderr
        os.unlink(sf.name)
        os.unlink(baseline_path)

    def test_baseline_only_suppresses_matching_findings(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
            sf.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")
            sf.flush()
            # Create baseline for this file
            baseline_path = sf.name + ".baseline.json"
            run_scan(sf.name, "--create-baseline", baseline_path)
            # Add a new secret on a different line
            with open(sf.name, "a") as f:
                f.write("TOKEN=ghp_R2D2C3POLukeSkywalkerHanSoloChewworx\n")
            # Scan with baseline — new secret should still be detected
            rc, stdout, _ = run_scan(sf.name, "--baseline", baseline_path, "--json")
        findings = json.loads(stdout)
        assert rc == 1
        assert any(f["rule_id"] == "github-pat" for f in findings)
        assert not any(f["rule_id"] == "aws-access-token" for f in findings)
        os.unlink(sf.name)
        os.unlink(baseline_path)

    def test_baseline_missing_file_no_error(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
            sf.write("nothing here\n")
            sf.flush()
            rc, _, _ = run_scan(sf.name, "--baseline", "/nonexistent/baseline.json")
        os.unlink(sf.name)
        assert rc == 0

    def test_custom_rules_ignores_default_rules(self):
        custom_rules = [
            {"id": "only-this", "description": "Only rule", "regex": "ONLYTHIS"}
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as rf:
            json.dump(custom_rules, rf)
            rf.flush()
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as sf:
                sf.write("KEY=AKIAZ7VRSQWB4XKHT5DO\n")
                sf.flush()
                rc, stdout, _ = run_scan(sf.name, "--rules", rf.name, "--json")
        os.unlink(rf.name)
        os.unlink(sf.name)
        findings = json.loads(stdout)
        assert rc == 0
        assert findings == []
