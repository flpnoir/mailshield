# MailShield

MailShield is a cybersecurity MVP that analyses email authentication controls using DNS checks.

Current features:
- SPF lookup + policy label (strict, soft, etc)
- DMARC lookup + policy label (none, quarantine, reject)
- Minimal Flask UI to analyse a domain and display results

Run:
- pip install -r requirements.txt
- python app/main.py
- open http://127.0.0.1:5000

Current status: Sprint 1, DNS lookup engine + basic web interface.
Next step: DKIM lookup (selector-based) and refine risk scoring.

