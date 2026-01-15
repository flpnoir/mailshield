import dns.resolver


def get_spf_record(domain: str) -> str:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(
                part.decode() if isinstance(part, (bytes, bytearray)) else str(part)
                for part in rdata.strings
            )
            if txt.lower().startswith("v=spf1"):
                return txt.strip()
        return ""
    except dns.resolver.NXDOMAIN:
        return ""
    except dns.resolver.NoAnswer:
        return ""
    except dns.resolver.Timeout:
        return ""
    except Exception:
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


if __name__ == "__main__":
    test_domains = ["yoobee.ac.nz", "google.com", "example.com"]

    for domain in test_domains:
        spf = get_spf_record(domain)

        print(f"\nDomain: {domain}")

        if spf:
            print(f"SPF: {spf}")
        else:
            print("SPF: not found")

        print(spf_policy_label(spf))
