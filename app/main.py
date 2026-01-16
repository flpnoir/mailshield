import re
from datetime import datetime, timezone
from flask import Flask, render_template, request, Response

from dns_lookup import (
    dns_status,
    get_spf_record,
    spf_policy_label,
    get_dmarc_record,
    dmarc_policy_label,
    get_dkim_record,
    dkim_status_label,
    risk_label,
)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None

    if request.method == "POST":
        domain = (request.form.get("domain") or "").strip().lower()
        selector = (request.form.get("selector") or "").strip().lower()

        # Normalise basic URL input
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.strip("/")

        if not domain:
            error = "Please enter a domain."
        elif "." not in domain or domain.startswith(".") or domain.endswith("."):
            error = "Please enter a valid domain (e.g. example.com)."
        else:
            status = dns_status(domain)

            if status != "ok":
                if status == "nxdomain":
                    error = "Domain does not exist (NXDOMAIN)."
                elif status == "timeout":
                    error = "DNS lookup timed out. Try again."
                else:
                    error = "DNS lookup failed. Consider checking your connection or try another domain."
            else:
                spf = get_spf_record(domain)
                dmarc = get_dmarc_record(domain)

                dkim = ""
                if selector:
                    dkim = get_dkim_record(domain, selector)

                results = {
                    "domain": domain,
                    "selector": selector,
                    "spf": spf if spf else "Not found",
                    "spf_policy": spf_policy_label(spf),
                    "dmarc": dmarc if dmarc else "Not found",
                    "dmarc_policy": dmarc_policy_label(dmarc),
                    "dkim": dkim if dkim else "Not found",
                    "dkim_status": dkim_status_label(dkim, selector),
                    "risk": risk_label(spf, dmarc, dkim, selector),
                }

    return render_template("index.html", results=results, error=error)


@app.route("/download_report", methods=["POST"])
def download_report():
    domain = (request.form.get("domain") or "").strip()
    selector = (request.form.get("selector") or "").strip()
    spf = (request.form.get("spf") or "Not found").strip()
    dmarc = (request.form.get("dmarc") or "Not found").strip()
    dkim = (request.form.get("dkim") or "Not found").strip()
    risk = (request.form.get("risk") or "Unknown").strip()

    safe_domain = re.sub(r"[^a-zA-Z0-9.-]+", "_", domain)[:80] or "domain"

    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    tool_version = "MailShield MVP v1.0"

    risk_note = (
        "Risk is an overall posture indicator based on SPF, DKIM and DMARC.\n"
        "It is not a guarantee of legitimacy, but helps identify less secure domain configurations."
    )

    report_content = (
        "MAILSHIELD SECURITY REPORT\n"
        "============================================================\n"
        f"Tool: {tool_version}\n"
        f"Generated: {generated_utc}\n"
        "------------------------------------------------------------\n"
        f"Domain: {domain}\n"
        f"DKIM Selector: {selector or 'Not provided'}\n"
        f"Overall Risk: {risk}\n"
        "------------------------------------------------------------\n"
        "NOTES\n"
        "------------------------------------------------------------\n"
        f"{risk_note}\n"
        "------------------------------------------------------------\n"
        "SPF\n"
        "------------------------------------------------------------\n"
        f"{spf}\n"
        "------------------------------------------------------------\n"
        "DMARC\n"
        "------------------------------------------------------------\n"
        f"{dmarc}\n"
        "------------------------------------------------------------\n"
        "DKIM\n"
        "------------------------------------------------------------\n"
        f"{dkim}\n"
        "============================================================\n"
        "End of report\n"
    )

    return Response(
        report_content,
        mimetype="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report_{safe_domain}.txt"'},
    )


if __name__ == "__main__":
    app.run(debug=True)
