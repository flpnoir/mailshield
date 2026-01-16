import dns.resolver


def get_txt_record(domain: str) -> list[str]:
    """
    Return TXT records for a domain. If lookup fails, return an empty list.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        records: list[str] = []

        for rdata in answers:
            # dnspython may return TXT strings as bytes segments
            parts = getattr(rdata, "strings", None)
            if parts:
                txt = "".join(
                    part.decode() if isinstance(part, (bytes, bytearray)) else str(part)
                    for part in parts
                )
            else:
                txt = str(rdata)

            records.append(txt.strip())

        return records

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def dns_status(domain: str) -> str:
    """
    Check whether a domain is resolvable using an NS query.
    Returns: ok | nxdomain | timeout | error
    """
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
    """
    Return the SPF record (v=spf1) if present, otherwise empty string.
    """
    for txt in get_txt_record(domain):
        if txt.lower().startswith("v=spf1"):
            return txt
    return ""


def spf_policy_label(spf_record: str) -> str:
    """
    Map SPF all-mechanism to a simple label.
    """
    spf = (spf_record or "").strip().lower()
    if not spf:
        return "Policy: not found"

    # Prefer explicit all mechanisms
    if spf.endswith(" -all") or spf.endswith("-all"):
        return "Policy: strict (-all)"
    if spf.endswith(" ~all") or spf.endswith("~all"):
        return "Policy: soft (~all)"
    if spf.endswith(" ?all") or spf.endswith("?all"):
        return "Policy: neutral (?all)"
    if spf.endswith(" +all") or spf.endswith("+all"):
        return "Policy: allow-all (+all)"
    if spf.endswith(" all"):
        return "Policy: allow-all (all)"

    return "Policy: unknown"


def get_dmarc_record(domain: str) -> str:
    """
    Return the DMARC record (v=DMARC1) under _dmarc.<domain>, otherwise empty string.
    """
    dmarc_domain = f"_dmarc.{domain}"
    for txt in get_txt_record(dmarc_domain):
        if txt.lower().startswith("v=dmarc1"):
            return txt
    return ""


def dmarc_policy_label(dmarc_record: str) -> str:
    """
    Return a simple label for DMARC policy tag p=.
    """
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
    """
    Extract DMARC p= value for scoring.
    Returns: reject | quarantine | none | unknown
    """
    rec = (dmarc_record or "").lower()
    if "p=reject" in rec:
        return "reject"
    if "p=quarantine" in rec:
        return "quarantine"
    if "p=none" in rec:
        return "none"
    return "unknown"


def get_dkim_record(domain: str, selector: str) -> str:
    """
    Return DKIM record if selector is provided and v=DKIM1 is found, otherwise empty string.
    """
    selector = (selector or "").strip()
    if not selector:
        return ""

    dkim_domain = f"{selector}._domainkey.{domain}"
    for txt in get_txt_record(dkim_domain):
        if "v=dkim1" in txt.lower():
            return txt
    return ""


def dkim_status_label(dkim_record: str, selector: str) -> str:
    """
    Human readable DKIM status label.
    """
    if not (selector or "").strip():
        return "DKIM: selector not provided"
    if dkim_record:
        return "DKIM: found"
    return "DKIM: not found"


def risk_label(spf_record: str, dmarc_record: str, dkim_record: str = "", selector: str = "") -> str:
    """
    Return a simple overall risk label: Low | Medium | High
    - High if DMARC missing/none/unknown or SPF missing
    - Low only when DMARC is reject and SPF is strict (-all)
      If selector is provided, DKIM must be found to confirm Low.
    - Otherwise Medium
    """
    spf_level = spf_policy_label(spf_record).lower()
    dmarc_p = extract_dmarc_policy(dmarc_record)

    if dmarc_p in ["unknown", "none"]:
        return "High"

    if not spf_record:
        return "High"

    low_candidate = ("strict" in spf_level) and (dmarc_p == "reject")

    # If selector was provided, require DKIM to confirm Low
    if (selector or "").strip():
        if low_candidate and dkim_record:
            return "Low"
        return "Medium"

    # If no selector, do not penalise for DKIM
    if low_candidate:
        return "Low"

    return "Medium"