# MailShield MVP

MailShield is a lightweight web tool that analyses a domain’s email security posture in real time by checking SPF, DKIM and DMARC DNS records.

## Purpose

Many New Zealand SMEs rely on email but often lack visibility over their domain security configuration. MailShield helps non specialist IT staff quickly understand whether a domain is configured to reduce spoofing and phishing risk.

## Features

- Real time DNS lookups for SPF, DKIM and DMARC  
- Basic risk scoring based on email authentication posture  
- Clear labels explaining each policy outcome  
- Downloadable TXT Technical Report  

## Installation

1. Clone the repository  
2. Create and activate a virtual environment (optional but recommended)  
3. Install dependencies:

```sh
pip install -r requirements.txt
```
Run the app:

```sh
python app/main.py
```
Open:
`http://127.0.0.1:5000/`

## Usage

- Enter a domain, for example `google.com`
- Optionally enter a DKIM selector
- Click Analyse
- Review SPF, DMARC and DKIM results with the risk label
- Click Download TXT Report to export the findings

## Evidence

Screenshots are available in the evidence/ folder, including:

- Valid domain without DKIM selector
- Valid domain with DKIM selector
- NXDOMAIN error case

## Notes

MailShield is an MVP designed for educational and diagnostic purposes. The risk label is indicative and does not guarantee legitimacy. A “Low” risk generally reflects a strict SPF policy (`-all`) combined with a DMARC policy of `p=reject`.