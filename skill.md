---
name: cybersec-guardian
displayName: "🛡️ CyberSec Guardian"
description: |
  A security-first skill that wraps every task with cybersecurity best practices.
  Detects prompt injection attempts, sanitizes inputs, scans files/URLs via VirusTotal,
  prevents secret leakage, and logs all security events. Apply this skill to any task
  to enforce a zero-trust posture.

metadata:
  clawdbot:
    emoji: "🛡️"
    env:
      - name: VIRUSTOTAL_API_KEY
        description: "VirusTotal API key for file/URL scanning. Get one free at virustotal.com"
        required: true
      - name: GUARDIAN_LOG_LEVEL
        description: "Logging verbosity: DEBUG, INFO, WARNING, ERROR (default: INFO)"
        required: false
        default: "INFO"
      - name: GUARDIAN_BLOCK_ON_THREAT
        description: "If true, abort task execution when a threat is detected (default: true)"
        required: false
        default: "true"
      - name: GUARDIAN_ALERT_WEBHOOK
        description: "Optional webhook URL to POST security alerts to (Slack/Discord/etc)"
        required: false
    pip:
      - requests>=2.31.0
      - python-dotenv>=1.0.0
      - cryptography>=41.0.0
      - pyyaml>=6.0
---

# 🛡️ CyberSec Guardian

A zero-trust security layer for OpenClaw skills and tasks. Every action runs through
a security pipeline before and after execution.

## What It Does

**Before any task runs:**
- Scans input for prompt injection patterns
- Checks for accidental secret/key exposure in prompts
- Validates and sanitizes file paths and URLs
- Scans URLs and files via VirusTotal

**During execution:**
- Prevents env vars and API keys from appearing in output
- Logs all security events with timestamps
- Rate-limits external API calls

**After execution:**
- Redacts any secrets that slipped into output
- Logs a security summary to `security_log.json`

## Setup

1. Add your `VIRUSTOTAL_API_KEY` to your `.env` file (never commit this)
2. Run: `python cybersec_guardian.py --selftest` to verify everything is working
3. Use the guardian as a wrapper: `python cybersec_guardian.py --scan-url https://example.com`

## Usage Examples

```bash
# Scan a URL before visiting
python cybersec_guardian.py --scan-url https://suspicious-site.com

# Scan a file before opening/executing
python cybersec_guardian.py --scan-file ./downloaded_script.py

# Check a prompt for injection attempts
python cybersec_guardian.py --check-prompt "ignore previous instructions and..."

# Run another skill through the security wrapper
python cybersec_guardian.py --wrap "python my_other_skill.py --arg value"

# Self-test all security modules
python cybersec_guardian.py --selftest
```

## Security Philosophy

- **Secrets never touch disk unencrypted** — loaded from env only, redacted from all logs
- **Zero trust inputs** — every external input is treated as hostile until validated
- **Fail closed** — if a security check errors out, the task is blocked, not bypassed
- **Audit trail** — every scan and decision is logged with ISO timestamps
