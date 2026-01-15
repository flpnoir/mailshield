# MailShield

MailShield is a cybersecurity MVP that analyses email authentication controls using DNS checks.

Current features:
- SPF lookup + policy label (strict, soft, etc)
- DMARC lookup + policy label (none, quarantine, reject)
- Minimal Flask UI to analyse a domain and display results

Current status: Sprint 1, DNS lookup engine + basic web interface.
Next: DKIM lookup (selector-based) and simple risk scoring.

