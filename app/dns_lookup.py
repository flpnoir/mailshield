import dns.resolver


def get_txt_record(domain: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            txt = "".join(
                part.decode() if isinstance(part, (bytes, bytearray)) else str(part)
                for part in rdata.strings
            )
            records.append(txt.strip())
        return records
    except Exception:
        return []


def dns_status(domain: str) -> str:
    try:
        dns.resolver.resolve(domain, "NS")
        return "ok"
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except dns.resolver.Timeout:
        return "timeout"
    except Exception:
        return "error"


def get_spf_record(domain: str) -> str:
    for txt in get_txt_record(domain):
        if txt.lower().startswith("v=spf1"):
            return txt
    return ""


def spf_policy_label(spf_record: str) -> str:
    spf = (spf_record or "").lower().strip()

    if not spf:
        return "Policy: not found"
    if spf.endswith("-all"):
        return "Policy: strict (-all)"
    if spf.endswith("~all"):
        return "Policy: soft (~all)"
    if spf.endswith("?all"):
        return "Policy: neutral (?all)"
    if spf.endswith("+all") or spf.endswith("all"):
        return "Policy: allow-all (all)"
    return "Policy: unknown"


def get_dmarc_record(domain: str) -> str:
    dmarc_domain = f"_dmarc.{domain}"
    for txt in get_txt_record(dmarc_domain):
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return ""


def dmarc_policy_label(dmarc_record: str) -> str:
    rec = (dmarc_record or "").lower()
    if not rec:
        return "Policy: not found"
    if "p=reject" in rec:
        return "Policy: reject"
    if "p=quarantine" in rec:
        return "Policy: quarantine"
    if "p=none" in rec:
        return "Policy: none"
    return "Policy: unknown"


def extract_dmarc_policy(dmarc_record: str) -> str:
    rec = (dmarc_record or "").lower()
    if "p=reject" in rec:
        return "reject"
    if "p=quarantine" in rec:
        return "quarantine"
    if "p=none" in rec:
        return "none"
    return "unknown"


def get_dkim_record(domain: str, selector: str) -> str:
    selector = (selector or "").strip()
    if not selector:
        return ""

    dkim_domain = f"{selector}._domainkey.{domain}"
    for txt in get_txt_record(dkim_domain):
        if "v=dkim1" in txt.lower():
            return txt
    return ""


def dkim_status_label(dkim_record: str, selector: str) -> str:
    if not (selector or "").strip():
        return "DKIM: selector not provided"
    if dkim_record:
        return "DKIM: found"
    return "DKIM: not found"


def risk_label(spf_record: str, dmarc_record: str, dkim_record: str = "", selector: str = "") -> str:
    spf_level = spf_policy_label(spf_record).lower()
    dmarc_p = extract_dmarc_policy(dmarc_record)

    if dmarc_p in ["unknown", "none"]:
        return "High"

    if not spf_record:
        return "High"

    low_candidate = ("strict" in spf_level) and (dmarc_p == "reject")

    # If selector was provided, require DKIM to confirm Low
    if selector:
        if low_candidate and dkim_record:
            return "Low"
        return "Medium"

    # If no selector, do not penalise for DKIM
    if low_candidate:
        return "Low"

    return "Medium"


if __name__ == "__main__":
    test_cases = [
        ("yoobee.ac.nz", ""),          # no selector
        ("google.com", "selector1"),   # likely not found
        ("yahoo.com", "selector1"),    # likely not found
        ("example.com", ""),           # strict SPF + reject DMARC (often Low by your rules)
    ]

    for domain, selector in test_cases:
        spf = get_spf_record(domain)
        dmarc = get_dmarc_record(domain)

        dkim = get_dkim_record(domain, selector) if selector else ""
        dkim_status = dkim_status_label(dkim, selector)

        risk = risk_label(spf, dmarc, dkim, selector)

        print(f"\nDomain: {domain}")
        if selector:
            print(f"Selector: {selector}")

        print(f"SPF: {spf}" if spf else "SPF: not found")
        print(spf_policy_label(spf))

        print(f"DMARC: {dmarc}" if dmarc else "DMARC: not found")
        print(dmarc_policy_label(dmarc))

        print(f"DKIM: {dkim}" if dkim else "DKIM: not found")
        print(dkim_status)

        print(f"Risk: {risk}")
