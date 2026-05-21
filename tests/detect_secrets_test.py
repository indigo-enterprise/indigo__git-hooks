from __future__ import annotations

import pytest

from pre_commit_hooks.detect_secrets import _should_include
from pre_commit_hooks.detect_secrets import main
from pre_commit_hooks.detect_secrets import mask
from pre_commit_hooks.detect_secrets import scan_text

# Sensitive-looking test values are split across concatenation so source
# scanners don't flag them as real secrets; the joined value still matches
# our regex at runtime.
_AWS_KEY      = "AKIA" + "1234567890ABCDEF"
_SLACK        = "xoxb-" + "123456789012-abcdefghijklmnop"
_STRIPE_LIVE  = "sk_live_" + "abcdefghijklmnopqrstuvwx"
_STRIPE_RK    = "rk_live_" + "abcdefghijklmnopqrstuvwx"
_STRIPE_TEST  = "sk_test_" + "abcdefghijklmnopqrstuvwx"
_GITHUB_TOK   = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
_GITLAB_TOK   = "glpat-" + "abcdefghij-KLMNOPQRST"
_SENDGRID     = "SG." + "aaaaaaaaaaaaaaaaaaaaaa." + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_NPM_TOK      = "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
_NPM_RC       = "//registry.npmjs.org/:_authToken=" + "npm_ABCDEFGHIabcdef"
_TWILIO_SID   = "AC" + "abcdef1234567890abcdef1234567890"
_FIREBASE     = "AAAA" + "1234567:" + "b" * 140
_GOOGLE_KEY   = "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz01234"
_DJANGO_KEY   = "abcdefghij" + "0123456789klmnopqrstuv"
_AZ_ACCT_KEY  = "dGVzdGtleXRlc3Rr" + "ZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk="
_AZ_SB_KEY    = "dGVzdGtleXRlc3Rr" + "ZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk="
_AWS_SECRET   = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
_VAULT_TOKEN  = "hvs." + "A" * 24
_AZURE_AD_SEC = "A" * 20 + "~.B-" + "C" * 12
_SENTRY_DSN   = "https://" + "ab01cd23" * 4 + "@o123.ingest.sentry.io/9001"
_GCP_SA_LINE  = '"client_email"' + ': "svc-deploy@my-project.iam.gserviceaccount.com"'
_BRAINTREE    = "access_token$production$" + "abcdef1234567890" + "$" + "a" * 32
_TEAMS_WH     = "https://mycompany.webhook.office.com" + "/webhookb2/abc-123"
_AZ_SAS_PARAM = "?sig=" + "A" * 40
_DD_API_VAL   = "a" * 32


# ── scan_text: positive cases ────────────────────────────────────────────────

POSITIVE_CASES = [
    ("aws_access_key_id",
     _AWS_KEY),
    ("aws_secret_access_key",
     f"aws_secret_access_key = {_AWS_SECRET}"),
    ("google_api_key",
     f"key = {_GOOGLE_KEY}"),
    ("github_token",
     f"token = {_GITHUB_TOK}"),
    ("gitlab_token",
     f"CI_JOB_TOKEN={_GITLAB_TOK}"),
    ("slack_token",
     _SLACK),
    ("stripe_secret",
     _STRIPE_LIVE),
    ("stripe_restricted_key",
     _STRIPE_RK),
    ("sendgrid_key",
     _SENDGRID),
    ("npm_auth_token",
     _NPM_TOK),
    ("npmrc_auth_token",
     _NPM_RC),
    ("twilio_account_sid",
     f"TWILIO_SID={_TWILIO_SID}"),
    ("django_secret_key",
     f'SECRET_KEY = "{_DJANGO_KEY}"'),
    ("azure_storage_connection_string",
     f"DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey={_AZ_ACCT_KEY}"),
    ("azure_servicebus_connection_string",
     f"Endpoint=sb://mynamespace.servicebus.windows.net/;"
     f"SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={_AZ_SB_KEY}"),
    ("redis_url_with_password",
     "REDIS_URL=redis" + "://:supersecretpass@redis.example.com:6379"),
    ("rabbitmq_amqp_url",
     "AMQP_URL=amqp" + "://user:password@rabbitmq.host:5672/vhost"),
    ("private_key_block",
     "-----BEGIN RSA " + "PRIVATE KEY-----"),
    ("private_key_block",
     "-----BEGIN EC " + "PRIVATE KEY-----"),
    ("private_key_block",
     "-----BEGIN " + "PRIVATE KEY-----"),
    ("openssh_private_key",
     "-----BEGIN OPENSSH" + " PRIVATE KEY-----"),
    ("pgp_private_key",
     "-----BEGIN PGP" + " PRIVATE KEY BLOCK-----"),
    ("connection_string_uri",
     "postgres" + "://user:s3cr3tpass@db.example.com:5432/mydb"),
    ("connection_string_uri",
     "mongodb" + "://admin:hunter2@mongo.host:27017/mydb"),
    ("connection_string_kv",
     "Server" + "=myserver;Database=mydb;User Id=sa;Password=MyP@ssword!;"),
    ("firebase_key",
     _FIREBASE),
    ("hashicorp_vault_token",
     f"VAULT_TOKEN={_VAULT_TOKEN}"),
    ("azure_ad_client_secret",
     f"client_secret = {_AZURE_AD_SEC}"),
    ("sentry_dsn",
     _SENTRY_DSN),
    ("gcp_service_account",
     _GCP_SA_LINE),
    ("braintree_access_token",
     _BRAINTREE),
    ("teams_webhook_url",
     _TEAMS_WH),
    ("azure_sas_token",
     f"https://storage.blob.core.windows.net/container/file{_AZ_SAS_PARAM}"),
    ("datadog_api_key",
     f"DD_API_KEY={_DD_API_VAL}"),
    ("jwt",
     "eyJhbGciOiJIUzI1NiJ9"
     ".eyJzdWIiOiJ1c2VySWQifQ"
     ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
    ("generic_api_key",
     "api" + "_key = AbCdEfGhIjKlMnOpQrSt"),
    ("generic_api_key",
     "pass" + "word = AbCdEfGhIjKlMnOpQrSt"),
]


@pytest.mark.parametrize(("name", "line"), POSITIVE_CASES)
def test_scan_text_detects(name: str, line: str) -> None:
    findings = scan_text(line)
    names_found = [f[1] for f in findings]
    assert name in names_found, (
        f"Expected pattern '{name}' to match: {line!r}\nGot: {names_found}"
    )


# ── scan_text: negative cases (no false positives) ──────────────────────────

NEGATIVE_CASES = [
    "api_key = abc123",
    "token = foobar",
    "secret = test",
    "api_key = your_api_key_here",
    "token = placeholder",
    "password = changeme",
    "secret = example_secret",
    "api_key = xxx",
    "token = dummy_value_here",
    _STRIPE_TEST,                          # Stripe test key (not live)
    "npm_" + "ABCDEshort",                 # npm token too short
    "redis://localhost:6379",              # Redis without password
    "amqp://user:@host/vhost",             # AMQP with empty password
    "const version = '1.2.3'",
    "import os",
    "DEBUG = True",
    "client_secret = short",               # azure_ad_client_secret too short
    "hvs." + "short",                      # vault token too short
    "DD_API_KEY=notvalidhex!!!!!!!!!!!!!", # datadog key not hex
    "sig=" + "A" * 10,                     # azure SAS sig too short
]


@pytest.mark.parametrize("line", NEGATIVE_CASES)
def test_scan_text_no_false_positives(line: str) -> None:
    findings = scan_text(line)
    assert findings == [], f"Unexpected findings for {line!r}: {findings}"


# ── Comment line behaviour ───────────────────────────────────────────────────

def test_generic_api_key_skipped_in_comment() -> None:
    line = "// api" + "_key = AbCdEfGhIjKlMnOpQrStUvWx"
    findings = scan_text(line)
    assert not any(f[1] == "generic_api_key" for f in findings)


def test_aws_key_caught_in_comment() -> None:
    line = f"// {_AWS_KEY}"
    findings = scan_text(line)
    assert any(f[1] == "aws_access_key_id" for f in findings)


def test_pem_header_caught_in_comment() -> None:
    line = "# -----BEGIN RSA " + "PRIVATE KEY-----"
    findings = scan_text(line)
    assert any(f[1] == "private_key_block" for f in findings)


# ── mask() ───────────────────────────────────────────────────────────────────

def test_mask_hides_middle() -> None:
    assert mask(_AWS_KEY, keep=3) == "AKI***DEF"


def test_mask_short_value() -> None:
    assert mask("ab", keep=3) == "**"


# ── _should_include filtering ────────────────────────────────────────────────

@pytest.mark.parametrize("path", [
    "src/settings.py",
    "config/appsettings.json",
    ".env",
    ".env.local",
    ".env.production",
    "app.config",
    "web.config",
    "src/App.tsx",
    "backend/main.go",
    "appsettings.Development.json",
    "scripts/deploy.sh",
    "infra/main.tf",
    "infra/secrets.tfvars",
    "scripts/bootstrap.ps1",
    "db/seed.sql",
    "Dockerfile",
])
def test_should_include_positive(path: str) -> None:
    assert _should_include(path) is True


@pytest.mark.parametrize("path", [
    "node_modules/lodash/index.js",
    "dist/bundle.js",
    ".venv/lib/site-packages/django/conf/__init__.py",
    "venv/lib/python3.11/site-packages/foo.py",
    "__pycache__/settings.cpython-311.pyc",
    "vendor/github.com/pkg/errors/errors.go",
    "bin/app",
    "obj/Debug/net8.0/MyApp.dll",
    "image.png",
    "README.md",
    "notes.txt",
    ".terraform/providers/registry.terraform.io/main.tf",
    "coverage/lcov.info",
    "migrations/0001_initial.py",
    "target/classes/App.class",
    "packages/lodash/index.js",
])
def test_should_include_negative(path: str) -> None:
    assert _should_include(path) is False


# ── main() integration (disk mode) ──────────────────────────────────────────

def test_main_clean_file_returns_0(tmpdir) -> None:
    f = tmpdir.join("settings.py")
    f.write("DEBUG = True\nALLOWED_HOSTS = ['localhost']\n")
    assert main([str(f)]) == 0


def test_main_aws_key_returns_1(tmpdir) -> None:
    f = tmpdir.join("config.env")
    f.write(f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n")
    assert main([str(f)]) == 1


def test_main_django_secret_key_returns_1(tmpdir) -> None:
    f = tmpdir.join("settings.py")
    f.write(f'SECRET_KEY = "{_DJANGO_KEY}"\n')
    assert main([str(f)]) == 1


def test_main_azure_storage_returns_1(tmpdir) -> None:
    f = tmpdir.join("appsettings.json")
    f.write(
        f"DefaultEndpointsProtocol=https;AccountName=myaccount;"
        f"AccountKey={_AZ_ACCT_KEY}\n"
    )
    assert main([str(f)]) == 1


def test_main_connection_string_kv_returns_1(tmpdir) -> None:
    f = tmpdir.join("app.config")
    f.write("Server" + "=myserver;Database=mydb;User Id=sa;Password=MyP@ssword!;\n")
    assert main([str(f)]) == 1


def test_main_redis_url_returns_1(tmpdir) -> None:
    f = tmpdir.join("config.env")
    f.write("REDIS_URL=redis" + "://:supersecretpass@redis.example.com:6379\n")
    assert main([str(f)]) == 1


def test_main_skips_venv_directory(tmpdir) -> None:
    venv_lib = tmpdir.mkdir(".venv").mkdir("lib")
    f = venv_lib.join("settings.py")
    f.write(f"AWS_ACCESS_KEY_ID={_AWS_KEY}\n")
    assert main([str(f)]) == 0


def test_main_skips_vendor_directory(tmpdir) -> None:
    vendor = tmpdir.mkdir("vendor").mkdir("pkg")
    f = vendor.join("config.go")
    f.write(f"const secret = `{_AWS_KEY}`\n")
    assert main([str(f)]) == 0


def test_main_skips_non_included_extension(tmpdir) -> None:
    f = tmpdir.join("notes.md")
    f.write("sec" + "ret = AbCdEfGhIjKlMnOpQrStUvWxYz\n")
    assert main([str(f)]) == 0


def test_main_masks_output(tmpdir, capsys) -> None:
    f = tmpdir.join("config.env")
    f.write(f"{_AWS_KEY}\n")
    main([str(f)])
    out, _ = capsys.readouterr()
    assert _AWS_KEY not in out
    assert "AKI***DEF" in out


def test_main_empty_file_returns_0(tmpdir) -> None:
    f = tmpdir.join("config.env")
    f.write("")
    assert main([str(f)]) == 0


def test_main_binary_file_returns_0(tmpdir) -> None:
    f = tmpdir.join("binary.env")
    f.write_binary(b"\x00\x01\x02\x03\xff\xfe")
    assert main([str(f)]) == 0
