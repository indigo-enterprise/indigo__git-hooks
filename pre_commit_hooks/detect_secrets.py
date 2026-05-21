#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
from typing import Iterable, List, Optional, Sequence, Tuple


def _c(name: str, pattern: str) -> Tuple[str, re.Pattern[str]]:
    return name, re.compile(pattern)


PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    # Generic — must be last resort; requires 20+ chars and excludes placeholders
    _c(
        "generic_api_key",
        r"(?i)\b(api[_-]?key|auth[_-]?key|x-api-key|access[_-]?key|client[_-]?secret"
        r"|client[_-]?id|token|secret|password)\b\s*(=|:)?\s*"
        r"[\"']?"
        r"(?!(?:example|your[_-]?|placeholder|changeme|change.me|xxx+|test|dummy|fake|sample|insert|todo|n/?a)\b)"
        r"[A-Za-z0-9_\-]{20,}"
        r"[\"']?",
    ),
    # AWS
    _c("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b"),
    _c(
        "aws_secret_access_key",
        r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
    ),
    # Google / GCP
    _c("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    # GitHub / GitLab
    _c("github_token", r"\bgh[pous]_[A-Za-z0-9]{36,}\b"),
    _c("gitlab_token", r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
    # Slack
    _c("slack_token", r"\bxox[baprs]-[A-Za-z0-9]{10,48}\b"),
    # Stripe
    _c("stripe_secret", r"\bsk_live_[A-Za-z0-9]{24}\b"),
    _c("stripe_restricted_key", r"\brk_live_[A-Za-z0-9]{24}\b"),
    # SendGrid
    _c(
        "sendgrid_key",
        r"\bSG\.[A-Za-z0-9\._-]{22}\.[A-Za-z0-9\._-]{43}\b",
    ),
    # npm
    _c("npm_auth_token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _c("npmrc_auth_token", r"//[^\s:]+:_authToken\s*=\s*[A-Za-z0-9_\-]{8,}"),
    # Twilio
    _c("twilio_account_sid", r"\bAC[a-f0-9]{32}\b"),
    # JWT
    _c(
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
    ),
    # Private keys — header-only (multiline matching against single lines never works)
    _c("private_key_block", r"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"),
    _c("openssh_private_key", "-----BEGIN OPENSSH" + " PRIVATE KEY-----"),
    _c("pgp_private_key", "-----BEGIN PGP" + " PRIVATE KEY BLOCK-----"),
    # Connection strings — URI format (postgres, mysql, mongodb, mssql, sqlserver, jdbc)
    _c(
        "connection_string_uri",
        r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|mssql|sqlserver"
        r"|jdbc:(?:mysql|postgresql|sqlserver))://[^\s'\"]+:[^\s'\"]+@",
    ),
    # Connection strings — SQL Server key=value (.NET ADO.NET)
    # Fires when Server has a real value (4+ chars) AND either:
    #   (a) Database/Initial Catalog has a value, OR
    #   (b) Password/Pwd has a value (4+ chars)
    # Env-var references (${VAR}, %VAR%, #{VAR}#, $(VAR)) in Server value are excluded.
    _c(
        "connection_string_kv",
        r"(?i)\b(?:Server|Data Source)=(?!\$\{|%[A-Z_]|\#\{|\$\()[^;'\"]{4,};(?:[^;]*;)*"
        r"(?:(?:(?:Database|Initial Catalog)=[^;'\"]+)|(?:(?:Password|Pwd)=(?!\$\{|%[A-Z_]|\#\{|\$\()[^;'\"]{4,}))",
    ),
    # Connection strings — .NET JSON appsettings (ConnectionStrings with embedded password=)
    _c(
        "connection_string_json",
        r"(?i)\b(ConnectionStrings|ConnectionString|DataSource)\b\s*[:=]\s*[\"'][^\"']*password=(?!\$\{|%[A-Z_]|\#\{|\$\()[^;\"']{4,}[^\"']*[\"']",
    ),
    # Azure Storage connection string
    _c(
        "azure_storage_connection_string",
        r"(?i)DefaultEndpointsProtocol\s*=\s*https?\s*;[^\"'\n]*AccountName\s*=[^;]+;"
        r"[^\"'\n]*AccountKey\s*=[A-Za-z0-9+/=]{44,}",
    ),
    # Azure Service Bus connection string
    _c(
        "azure_servicebus_connection_string",
        r"(?i)Endpoint\s*=\s*sb://[^;]+;[^\"'\n]*SharedAccessKeyName\s*=[^;]+;"
        r"[^\"'\n]*SharedAccessKey\s*=[A-Za-z0-9+/=]{40,}",
    ),
    # Django SECRET_KEY
    _c(
        "django_secret_key",
        r"(?i)\bSECRET_KEY\s*=\s*[\"'][A-Za-z0-9!@#$%^&*()\-_=+\[\]{};:,./?]{20,}[\"']",
    ),
    # Redis URL with embedded password
    _c("redis_url_with_password", "(?i)redis" + r"://:[^\s@]+" + r"@[^\s/\"']+"),
    # RabbitMQ AMQP URL with credentials
    _c(
        "rabbitmq_amqp_url",
        "(?i)amqp" + r"s?://[^\s:@/\"']+:[^\s@/\"']{4,}" + r"@[^\s/\"']+",
    ),
    # Firebase
    _c("firebase_key", r"\bAAAA[A-Za-z0-9_\-]{7,}:[A-Za-z0-9_\-]{140,}\b"),
    # HashiCorp Vault service token
    _c("hashicorp_vault_token", r"\bhvs\.[A-Za-z0-9_\-]{24,}\b"),
    # Azure AD / Entra ID client secret
    _c(
        "azure_ad_client_secret",
        r"(?i)client[_-]?secret\s*[:=]\s*[\"']?[A-Za-z0-9~._\-]{32,}[\"']?",
    ),
    # Sentry DSN
    _c(
        "sentry_dsn",
        r"https://[a-f0-9]{32}@[^/]+\.ingest(?:\.us)?\.sentry\.io/[0-9]+",
    ),
    # GCP service account email (from JSON key file)
    _c(
        "gcp_service_account",
        r'"client_email"\s*:\s*"[^@\"]+@[^.\"]+\.iam\.gserviceaccount\.com"',
    ),
    # Braintree access token
    _c(
        "braintree_access_token",
        r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    ),
    # Microsoft Teams incoming webhook URL
    _c(
        "teams_webhook_url",
        r"https://[a-z0-9]+\.webhook\.office\.com/webhookb2/",
    ),
    # Azure SAS token (query string signature)
    _c("azure_sas_token", r"(?i)[?&]sig=[A-Za-z0-9%+/]{40,}"),
    # Datadog API key
    _c("datadog_api_key", r"(?i)\bDD_API_KEY\s*[:=]\s*[a-f0-9]{32}\b"),
)

COMMENT_LINE = re.compile(r"^\s*(//|/\*|\*|#|;|--|'|\s*\*\s)")

INCLUDE_EXTS = {
    ".cs", ".csproj", ".props", ".targets",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".xml",
    ".go", ".env",
    ".py", ".config",
    ".sh", ".ps1",
    ".tf", ".tfvars",
    ".sql",
}

INCLUDE_FILENAMES = {
    "appsettings.json",
    "appsettings.Development.json",
    "appsettings.Production.json",
    "secrets.json",
    "package.json",
    "vite.config.ts",
    "vite.config.js",
    "Dockerfile",
    "dockerfile",
}

EXCLUDED_DIR_PARTS = {
    "node_modules", "dist", "build", "out", "bin", "obj", ".git",
    ".venv", "venv", "__pycache__", "vendor",
    ".terraform", "coverage", "migrations", "target", "packages",
}


def _should_include(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    if any(p in EXCLUDED_DIR_PARTS for p in parts):
        return False
    basename = parts[-1]
    if basename in INCLUDE_FILENAMES:
        return True
    _, _, ext = basename.rpartition(".")
    if ext and f".{ext.lower()}" in INCLUDE_EXTS:
        return True
    if basename.startswith(".env"):
        return True
    return False


def is_binary(data: bytes) -> bool:
    allowed = {7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100))
    return bool(data[:8000].translate(None, bytes(allowed)))


def _decode(content: bytes) -> Optional[str]:
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return content.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _git_staged_files() -> List[str]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        capture_output=True,
    )
    raw = result.stdout.decode("utf-8", errors="ignore")
    return [p for p in raw.split("\x00") if p and _should_include(p)]


def _git_show_index(path: str) -> Optional[bytes]:
    result = subprocess.run(
        ["git", "show", f":{path}"],
        capture_output=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout


def _read_disk(path: str) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def mask(s: str, keep: int = 2) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}***{s[-keep:]}"


def _iter_matches(line: str) -> Iterable[Tuple[str, str]]:
    for name, rx in PATTERNS:
        for m in rx.finditer(line):
            yield name, m.group(0)


def scan_text(text: str) -> List[Tuple[int, str, str]]:
    findings: List[Tuple[int, str, str]] = []
    for i, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        line_is_comment = bool(COMMENT_LINE.match(line))
        for name, value in _iter_matches(line):
            # Suppress only the noisy generic pattern on comment lines;
            # structural secrets (AWS keys, PEM headers, etc.) are flagged regardless.
            if line_is_comment and name == "generic_api_key":
                continue
            findings.append((i, name, value))
    return findings


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Detect hardcoded secrets")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)

    if args.files:
        file_list = [f for f in args.files if _should_include(f)]
        read_fn = _read_disk
    else:
        file_list = _git_staged_files()
        read_fn = _git_show_index  # type: ignore[assignment]

    all_findings: List[Tuple[str, int, str, str]] = []

    for path in file_list:
        content = read_fn(path)
        if content is None:
            continue
        if is_binary(content):
            continue
        text = _decode(content)
        if text is None:
            continue
        for line_num, name, value in scan_text(text):
            all_findings.append((path, line_num, name, value))

    if all_findings:
        print("Se detectaron posibles secretos expuestos:")
        for path, line_num, name, value in all_findings:
            print(f"  - {path}:{line_num} [{name}] => {mask(value, keep=3)}")
        print("\nBloqueando el commit. Revise y elimine/oculte estos valores.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
