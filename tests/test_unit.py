"""Unit tests for secret_detect.py core functions."""
import json
import sys
import os
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secret_detect import (
    shannon_entropy,
    is_allowlisted_path,
    is_false_positive,
    scan_line,
    load_rules,
    load_config,
)

RULES = load_rules()
CONFIG = load_config()


# --- shannon_entropy ---

class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        ent = shannon_entropy("aB3$xZ9!qW7@")
        assert ent > 3.0

    def test_low_entropy(self):
        ent = shannon_entropy("aaaaab")
        assert ent < 1.0


# --- is_allowlisted_path ---

class TestAllowlistedPath:
    def test_git_dir(self):
        assert is_allowlisted_path(".git/objects/abc", CONFIG["allowlist_paths"]) is True

    def test_node_modules(self):
        assert is_allowlisted_path("foo/node_modules/pkg/index.js", CONFIG["allowlist_paths"]) is True

    def test_minified_js(self):
        assert is_allowlisted_path("dist/bundle.min.js", CONFIG["allowlist_paths"]) is True

    def test_image(self):
        assert is_allowlisted_path("assets/logo.png", CONFIG["allowlist_paths"]) is True

    def test_normal_file(self):
        assert is_allowlisted_path("src/main.py", CONFIG["allowlist_paths"]) is False

    def test_lock_files(self):
        assert is_allowlisted_path("package-lock.json", CONFIG["allowlist_paths"]) is True
        assert is_allowlisted_path("yarn.lock", CONFIG["allowlist_paths"]) is True


# --- is_false_positive ---

class TestFalsePositive:
    def test_example_keyword(self):
        assert is_false_positive("EXAMPLE_KEY_HERE", CONFIG["allowlist_stopwords"]) is True

    def test_placeholder(self):
        assert is_false_positive("placeholder_value", CONFIG["allowlist_stopwords"]) is True

    def test_repeated_chars(self):
        assert is_false_positive("aaaaaaaaaaaaaaaa", CONFIG["allowlist_stopwords"]) is True

    def test_real_looking_secret(self):
        assert is_false_positive("Abc123Def456Ghi789", CONFIG["allowlist_stopwords"]) is False


# --- scan_line ---

class TestScanLine:
    def test_aws_key(self):
        line = "AWS_KEY=AKIAZ7VRSQWB4XKHT5DO"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "aws-access-token" in rule_ids

    def test_github_pat(self):
        line = "token=ghp_R2D2C3POLukeSkywalkerHanSoloChewworx"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "github-pat" in rule_ids

    def test_private_key(self):
        line = "-----BEGIN RSA PRIVATE KEY-----"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "private-key" in rule_ids

    def test_jwt(self):
        line = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "jwt" in rule_ids

    def test_slack_webhook(self):
        line = "SLACK=https://hooks.slack.com/services/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"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "slack-webhook" in rule_ids

    def test_stripe_key(self):
        line = "STRIPE_KEY=sk_live_AbCdEfGhIjKlMnOpQrStUvWx"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "stripe-secret-key" in rule_ids

    def test_google_api_key(self):
        line = "GOOGLE_KEY=AIzaSyBnMpQrStUvWxYzHjKlTgRsDfGhJkLqWeR"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        rule_ids = [r[0]["id"] for r in results]
        assert "google-api-key" in rule_ids

    def test_no_match_clean_line(self):
        line = "print('hello world')"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert results == []

    def test_false_positive_filtered(self):
        line = 'api_key = "EXAMPLE_KEY_PLACEHOLDER"'
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert results == []

    def test_low_entropy_filtered(self):
        line = 'api_key = "aaaaaaaaaaaaaaaaaaaaaa"'
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert results == []


# --- load_rules ---

class TestLoadRules:
    def test_load_default_rules(self):
        rules = load_rules()
        assert isinstance(rules, list)
        assert len(rules) > 0
        rule_ids = {r["id"] for r in rules}
        assert "aws-access-token" in rule_ids
        assert "github-pat" in rule_ids
        assert "private-key" in rule_ids

    def test_every_rule_has_required_fields(self):
        rules = load_rules()
        for rule in rules:
            assert "id" in rule
            assert "regex" in rule
            assert "description" in rule

    def test_load_custom_rules_file(self):
        custom_rules = [
            {"id": "custom-rule", "description": "Custom", "regex": "SECRET_[A-Z]+"}
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_rules, f)
            f.flush()
            rules = load_rules(f.name)
        os.unlink(f.name)
        assert len(rules) == 1
        assert rules[0]["id"] == "custom-rule"

    def test_custom_rules_used_for_scanning(self):
        custom_rules = [
            {"id": "custom-rule", "description": "Custom", "regex": "MYSECRET_[A-Z]{10,}"}
        ]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(custom_rules, f)
            f.flush()
            rules = load_rules(f.name)
        os.unlink(f.name)
        results = scan_line("token=MYSECRET_ABCDEFGHIJ", rules, CONFIG["allowlist_stopwords"])
        assert len(results) == 1
        assert results[0][0]["id"] == "custom-rule"

    def test_load_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules("/nonexistent/rules.json")

    def test_load_invalid_json_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("not valid json {{{")
            f.flush()
            with pytest.raises(json.JSONDecodeError):
                load_rules(f.name)
        os.unlink(f.name)

    def test_load_rule_missing_id_raises(self):
        bad_rules = [{"description": "No id", "regex": "foo"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(bad_rules, f)
            f.flush()
            with pytest.raises(ValueError, match="missing required"):
                load_rules(f.name)
        os.unlink(f.name)

    def test_load_rule_missing_regex_raises(self):
        bad_rules = [{"id": "no-regex", "description": "No regex"}]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(bad_rules, f)
            f.flush()
            with pytest.raises(ValueError, match="missing required"):
                load_rules(f.name)
        os.unlink(f.name)


# --- Entropy filtering per rule ---

class TestEntropyFiltering:
    """Verify that entropy thresholds from gitleaks are enforced on all applicable rules."""

    def test_aws_key_low_entropy_rejected(self):
        """AKIAIOSFODNN7TESTING has entropy ~3.45, below the 3.8 threshold."""
        line = "KEY=AKIAIOSFODNN7TESTING"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "aws-access-token" for r in results)

    def test_aws_key_high_entropy_accepted(self):
        line = "KEY=AKIAZ7VRSQWB4XKHT5DO"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "aws-access-token" for r in results)

    def test_github_pat_low_entropy_rejected(self):
        """ghp_ followed by repeating chars should be rejected (entropy < 3)."""
        line = "token=ghp_AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "github-pat" for r in results)

    def test_github_pat_high_entropy_accepted(self):
        line = "token=ghp_R2D2C3POLukeSkywalkerHanSoloChewworx"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "github-pat" for r in results)

    def test_gitlab_pat_low_entropy_rejected(self):
        line = "token=glpat-AAAAAAAAAAAAAAAAAAAA"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "gitlab-pat" for r in results)

    def test_gitlab_pat_high_entropy_accepted(self):
        line = "token=glpat-R2d5X9bK7mNpQsWvYzLt"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "gitlab-pat" for r in results)

    def test_stripe_key_low_entropy_rejected(self):
        line = "key=sk_live_AAAAAAAAAAAAAAAAAAAAAAAA"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "stripe-secret-key" for r in results)

    def test_stripe_key_high_entropy_accepted(self):
        line = "key=sk_live_AbCdEfGhIjKlMnOpQrStUvWx"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "stripe-secret-key" for r in results)

    def test_jwt_low_entropy_rejected(self):
        line = "token=eyJhbGciOiAAAAAAAAAAAA"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "jwt" for r in results)

    def test_jwt_high_entropy_accepted(self):
        line = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "jwt" for r in results)

    def test_google_api_key_low_entropy_rejected(self):
        line = "key=AIzaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "google-api-key" for r in results)

    def test_google_api_key_high_entropy_accepted(self):
        line = "key=AIzaSyBnMpQrStUvWxYzHjKlTgRsDfGhJkLqWeR"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "google-api-key" for r in results)

    def test_twilio_key_low_entropy_rejected(self):
        line = "key=SKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert not any(r[0]["id"] == "twilio-api-key" for r in results)

    def test_twilio_key_high_entropy_accepted(self):
        line = "key=SK8f3a1b2c9d4e5f6a7b8c9d0e1f2a3b4c"
        results = scan_line(line, RULES, CONFIG["allowlist_stopwords"])
        assert any(r[0]["id"] == "twilio-api-key" for r in results)

    def test_all_rules_have_entropy_except_private_key_and_webhooks(self):
        """Verify alignment with gitleaks: almost all rules should have entropy."""
        rules = load_rules()
        no_entropy_allowed = {"private-key", "slack-webhook", "heroku-api-key"}
        for rule in rules:
            if rule["id"] not in no_entropy_allowed:
                assert "entropy" in rule and rule["entropy"] > 0, (
                    f"Rule '{rule['id']}' should have an entropy threshold (per gitleaks)"
                )
