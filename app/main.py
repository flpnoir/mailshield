from flask import Flask, render_template, request

from dns_lookup import (
    dns_status,
    get_spf_record,
    spf_policy_label,
    get_dmarc_record,
    dmarc_policy_label,
    risk_label,
)

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    error = None

    if request.method == "POST":
        domain = (request.form.get("domain") or "").strip().lower()

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
                    error = "DNS lookup failed. Please try another domain."
            else:
                spf = get_spf_record(domain)
                dmarc = get_dmarc_record(domain)

                results = {
                    "domain": domain,
                    "spf": spf if spf else "not found",
                    "spf_policy": spf_policy_label(spf),
                    "dmarc": dmarc if dmarc else "not found",
                    "dmarc_policy": dmarc_policy_label(dmarc),
                    "risk": risk_label(spf, dmarc),
                }

    return render_template("index.html", results=results, error=error)


if __name__ == "__main__":
    app.run(debug=True)
