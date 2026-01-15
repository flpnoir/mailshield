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


def get_spf_record(domain: str) -> str:
    for txt in get_txt_record(domain):
        if txt.lower().startswith("v=spf1"):
            return txt
    return ""


def spf_policy_label(spf_record: str) -> str:
    spf = spf_record.lower().strip()
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
    rec = dmarc_record.lower()
    if not rec:
        return "Policy: not found"

    # DMARC policy is p=...
    if "p=reject" in rec:
        return "Policy: reject"
    if "p=quarantine" in rec:
        return "Policy: quarantine"
    if "p=none" in rec:
        return "Policy: none"

    return "Policy: unknown"


if __name__ == "__main__":
    test_domains = ["yoobee.ac.nz", "google.com", "example.com"]

    for domain in test_domains:
        spf = get_spf_record(domain)
        dmarc = get_dmarc_record(domain)

        print(f"\nDomain: {domain}")

        if spf:
            print(f"SPF: {spf}")
        else:
            print("SPF: not found")
        print(spf_policy_label(spf))

        if dmarc:
            print(f"DMARC: {dmarc}")
        else:
            print("DMARC: not found")
        print(dmarc_policy_label(dmarc))
