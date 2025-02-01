#!/usr/bin/env python3
import sys
import re
import subprocess

# Patrones de expresiones regulares para detectar información sensible
SENSITIVE_PATTERNS = [
   # Claves y secretos comunes
    r'(?i)(client_?id|client_?secret|api_?key|token|password|secret)(=|:|\s+)(["\'])?\w+(["\'])?',

    # AWS Keys
    r'(?i)aws_access_key_id(=|:|\s+)(["\'])?AKIA[0-9A-Z]{16}(["\'])?',
    r'(?i)aws_secret_access_key(=|:|\s+)(["\'])?\w{40}(["\'])?',

    # Cadenas de conexión (bases de datos y URLs con credenciales)
    r'(?i)(postgres(ql)?|mysql|mongodb(\+srv)?|sqlserver|jdbc:(mysql|postgresql|sqlserver))://[^:]+:[^@]+@',
    r'(?i)Server=[^;]+;Database=[^;]+;(User\s*Id|Uid)=[^;]+;(Password|Pwd)=[^;]+;',
    r'(?i)(ConnectionString|DataSource)(=|\s*:)\s*["\'][^"\']*[Pp]assword=[^"\']*["\']',
    r'(?i)"DefaultConnection"\s*:\s*"[^"]*[Pp]assword=[^";]*"',
    r'(?i)Initial\s*Catalog\s*=\s*[^;]+;User\s*ID\s*=\s*[^;]+;Password\s*=\s*[^;]+',

    # Credenciales en formato clave-valor
    r'(?i)(\b|_)(user|username|uid|userid|pass|pwd|creds|credentials)(\b|_)\s*[=:]\s*["\']?[^"\'\s<>]+',

     # Claves de API de Google
    r'AIza[0-9A-Za-z-_]{35}',

    # Claves de API de Slack
    r'xox[baprs]-[0-9a-zA-Z]{10,48}',

    # Claves de API de Stripe
    r'sk_live_[0-9a-zA-Z]{24}',

    # Claves de API de Twilio
    r'SK[0-9a-fA-F]{32}',

    # Claves de API de GitHub
    r'ghp_[0-9a-zA-Z]{36}',

    # Claves de API de Facebook
    r'EAACEdEose0cBA[0-9A-Za-z]+',

    # Claves de API de Amazon MWS
    r'amzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',

    # Claves de API de MailChimp
    r'[0-9a-f]{32}-us[0-9]{1,2}',

    # Claves de API de SendGrid
    r'SG\.[0-9A-Za-z\.\-_]{22}\.[0-9A-Za-z\.\-_]{43}',

    # Claves de API de Heroku
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',

    # Claves de API de Dropbox
    r'dropbox:[0-9a-zA-Z]{15}',

    # Claves de API de LinkedIn
    r'linkedin:[0-9a-zA-Z]{12}',

    # Claves de API de PayPal
    r'paypal:[0-9a-zA-Z]{17}',

    # Claves de API de AWS
    r'AKIA[0-9A-Z]{16}',

    # Claves secretas de AWS
    r'(?i)aws_secret_access_key\s*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?',

    # Claves de API de Azure
    r'azure_[0-9a-zA-Z]{32}',

    # Claves de API de GCP
    r'AIza[0-9A-Za-z-_]{35}',

    # Claves de API de DigitalOcean
    r'do_[0-9a-f]{64}',

    # Claves de API de GitLab
    r'glpat-[0-9a-zA-Z\-_]{20}',

    # Claves de API de Bitbucket
    r'bbp_[0-9a-zA-Z]{32}',

    # Claves de API de Atlassian
    r'atl_[0-9a-zA-Z]{24}',

    # Claves de API de Shopify
    r'shpss_[0-9a-fA-F]{32}',

    # Claves de API de Square
    r'sq0atp-[0-9A-Za-z\-_]{22}',

    # Claves de API de HubSpot
    r'pat-[0-9a-fA-F]{32}',

    # Claves de API de Zendesk
    r'zdsk_[0-9a-zA-Z]{32}',

    # Claves de API de Intercom
    r'ic_[0-9a-zA-Z]{32}',

    # Claves de API de Segment
    r'seg_[0-9a-zA-Z]{32}',

    # Claves de API de Algolia
    r'algolia_[0-9a-zA-Z]{32}',

    # Claves de API de Sentry
    r'sentry_[0-9a-zA-Z]{32}',

    # Claves de API de Datadog
    r'dd_[0-9a-zA-Z]{32}',

    # Claves de API de New Relic
    r'nr_[0-9a-zA-Z]{32}',

    # Claves de API de PagerDuty
    r'pd_[0-9a-zA-Z]{32}',

    # Claves de API de Rollbar
    r'rollbar_[0-9a-zA-Z]{32}',

    # Claves de API de Bugsnag
    r'bugsnag_[0-9a-zA-Z]{32}',

    # Claves de API de Honeybadger
    r'hb_[0-9a-zA-Z]{32}',

    # Claves de API de Airbrake
    r'ab_[0-9a-zA-Z]{32}',

    # Claves de API de Raygun
    r'rg_[0-9a-zA-Z]{32}',

    # Claves de API de Loggly
    r'loggly_[0-9a-zA-Z]{32}',

    # Claves de API de Papertrail
    r'pt_[0-9a-zA-Z]{32}',

    # Claves de API de Logentries
    r'le_[0-9a-zA-Z]{32}',

    # Claves de API de Logz.io
    r'logzio_[0-9a-zA-Z]{32}',

    # Claves de API de Sumologic
    r'sumo_[0-9a-zA-Z]{32}',

    # Claves de API de Splunk
    r'splunk_[0-9a-zA-Z]{32}',

    # Claves de API de Graylog
    r'graylog_[0-9a-zA-Z]{32}',

    # Claves de API de Fluentd
    r'fluentd_[0-9a-zA-Z]{32}',

    # Claves de API de Logstash
    r'logstash_[0-9a-zA-Z]{32}',

    # Claves de API de Kibana
    r'kibana_[0-9a-zA-Z]{32}',

    # Claves de API de Grafana
    r'grafana_[0-9a-zA-Z]{32}',

    # Claves de API de Prometheus
    r'prometheus_[0-9a-zA-Z]{32}',

    # Claves de API de Alertmanager
    r'alertmanager_[0-9a-zA-Z]{32}',
]

# Archivos o directorios a excluir (ej: .env, configs permitidas)
EXCLUDED_PATHS = [
    '*.env',
    'config/local.yaml'
]

def get_staged_files():
    """Obtiene la lista de archivos en staging."""
    result = subprocess.run(
        ['git', 'diff', '--cached', '--name-only'],
        capture_output=True,
        text=True
    )
    return result.stdout.splitlines()

def is_excluded(file_path):
    """Verifica si el archivo está en la lista de excluidos."""
    from fnmatch import fnmatch
    return any(fnmatch(file_path, pattern) for pattern in EXCLUDED_PATHS)

def scan_file(file_path):
    """Escanea un archivo en busca de patrones sensibles."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except UnicodeDecodeError:
        return []  # Saltar archivos binarios
    
    findings = []
    for pattern in SENSITIVE_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE):
            findings.append(pattern)
    return findings

def main():
    staged_files = get_staged_files()
    has_errors = False

    for file_path in staged_files:
        if is_excluded(file_path):
            continue

        findings = scan_file(file_path)
        if findings:
            print(f"Error: Archivo '{file_path}' contiene patrones sensibles:")
            for pattern in findings:
                print(f"  - Patron detectado: {pattern}")
            has_errors = True

    if has_errors:
        sys.exit(1)
    else:
        print("No se detectaron credenciales expuestas.")
        sys.exit(0)

if __name__ == "__main__":
    main()