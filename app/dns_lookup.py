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


def risk_label(spf_record: str, dmarc_record: str) -> str:
    spf_level = spf_policy_label(spf_record).lower()
    dmarc_p = extract_dmarc_policy(dmarc_record)

    # High if DMARC missing or weak
    if dmarc_p in ["unknown", "none"]:
        return "High"

    # High if SPF missing
    if not spf_record:
        return "High"

    # Low only when both are strict
    if ("strict" in spf_level) and (dmarc_p == "reject"):
        return "Low"

    # Everything else
    return "Medium"



if __name__ == "__main__":
    test_domains = ["yoobee.ac.nz", "google.com", "example.com"]

    for domain in test_domains:
        spf = get_spf_record(domain)
        dmarc = get_dmarc_record(domain)
        risk = risk_label(spf, dmarc)

        print(f"\nDomain: {domain}")

        print(f"SPF: {spf}" if spf else "SPF: not found")
        print(spf_policy_label(spf))

        print(f"DMARC: {dmarc}" if dmarc else "DMARC: not found")
        print(dmarc_policy_label(dmarc))

        print(f"Risk: {risk}")
