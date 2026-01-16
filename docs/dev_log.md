## Sprint 1 – Day 1

Work done:
- Created the initial project structure and connected the local repository to GitHub.
- Installed dnspython and verified the Python environment.
- Created the first DNS module and ran a basic execution test.

Learnings:
- Revisited Python dependency management using requirements.txt.
- Understood how DNS-related libraries are loaded and executed in a local environment.

## Sprint 1 – Day 2

Work done:
- Implemented a simple SPF policy label based on the SPF all mechanism (-all, ~all, ?all, all).
- Printed the SPF record and the policy result for real test domains.

Learnings:
- The SPF policy strength is often communicated through the all mechanism at the end of the record.
- A small label like “strict” or “soft” makes the output easier to read and helps later scoring.

## Sprint 1 – Day 3

Work done:
- Added DMARC lookup by querying TXT records for _dmarc.<domain>.
- Parsed DMARC policy (p=none, quarantine, reject) and printed a simple label.
- Tested SPF and DMARC output against real domains.

Learnings:
- DMARC is published under the _dmarc subdomain, not the root domain.
- The p= tag communicates how receivers should handle emails that fail authentication.

## Sprint 1 – Day 4

Work done:
- Installed Flask and added it to requirements.txt.
- Built a minimal page to submit a domain and run the checks in the browser.
- Reused the DNS engine in dns_lookup.py and returned SPF, DMARC and risk in the UI.
- Saved screenshots of real domain results for evidence (Low and Medium cases).
- Adjusted risk scoring to treat missing or weak DMARC as High risk.

Learnings:
- A Flask route is basically: get input, run the functions, render the result.
- Keeping the engine separate makes terminal testing quicker and the UI simpler.

## Sprint 1 – Day 5

Work done:
- Updated the risk scoring rules so DMARC missing or p=none shows High.
- Set Low risk only when DMARC is reject and SPF ends with -all.

Learnings:
- A clear rule set makes the output easier to justify in the report, not just “whatever the script prints”.
- Real domains vary a lot, so the scoring has to handle missing records properly.
- Added DNS status checks (NXDOMAIN/timeout) to keep the UI stable.

## Sprint 2 – Day 6

Work done:
- Added DKIM lookup using manual selector with <selector>._domainkey.<domain>.
- Updated Flask UI to accept an optional selector and display DKIM results.
- Added DKIM status label (selector not provided, found, not found).
- Updated risk scoring to require DKIM only when a selector is provided.
- Captured evidence screenshot showing a valid DKIM record (google.com + selector 20230601).

Learnings:
- DKIM records are selector-based, so “not found” is expected when the selector is wrong.
- Keeping DKIM optional avoids false negatives when the selector is unknown.
- Risk scoring needs to be consistent with what the user can realistically provide.

## Sprint 2 – Day 7

Work done:
- Added a Flask route /download_report to generate a downloadable TXT Technical Report.
- Passed results from the UI to the backend using hidden form fields in index.html.
- Improved the report format with tool version and UTC timestamp.
- Added clear section separators (SPF, DMARC, DKIM) plus a short risk explanation note.
- Tested the report export using google.com with selector 20230601 and confirmed the TXT downloads correctly.
- Created and organised an evidence/ folder with screenshots for valid results and controlled errors (NXDOMAIN).

Learnings:
- A report export feature turns a simple checker into a client friendly deliverable.
- Keeping UI values consistent (Not found, selector optional) avoids confusing outputs in the report.
- Clean formatting and evidence screenshots improve traceability and make results easier to validate.