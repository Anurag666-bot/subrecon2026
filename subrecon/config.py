"""
Configuration module for SubRecon 2026.
"""
import json

# Common words for permutation and brute-force
COMMON_WORDS = [
    "www", "api", "admin", "dev", "test", "staging", "prod", "prod-api",
    "vpn", "mail", "remote", "portal", "app", "cdn", "static", "assets",
    "media", "files", "download", "ftp", "sftp", "ssh", "git", "jenkins",
    "grafana", "prometheus", "kibana", "elastic", "kafka", "redis", "mongo",
    "mysql", "postgres", "db", "backup", "logs", "monitor", "status"
]

# Permutation rules
PERMUTATION_RULES = [
    ("-api", "api-"), ("-admin", "admin-"), ("-dev", "dev-"), ("-test", "test-"),
    ("-stage", "stage-"), ("-prod", "prod-"), ("-backup", "backup-"), ("-old", "old-"),
    ("-new", "new-"), ("-v2", "v2-"), ("-internal", "internal-")
]

# Try to load API keys from config.json
try:
    with open('config.json') as f:
        KEYS = json.load(f)
except:
    KEYS = {}