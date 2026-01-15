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
