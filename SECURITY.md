# Security policy

## Supported versions
Only the latest commit on `main` is maintained. This is a portfolio project, not a released product.

## Reporting a vulnerability
Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting (the "Report a vulnerability" button on the repository's Security tab) if it is shown, or contact the maintainer through the GitHub profile `@faroukkhaled`. I will answer when I can. There is no bug bounty and no guaranteed response time.

## What counts
`ad-sysmon-lab` reads event files you give it (XML, JSONL, CSV) and rule files (YAML). Bugs that crash it or run code on crafted input are in scope. The PowerShell scripts in `scripts/` change Windows settings and are meant for an isolated lab only.

Findings about the detection rules themselves (missed attacks, false positives) are normal bugs: open a regular issue.

## Safe use
All sample data is synthetic or from public datasets. Do not put real credentials, customer data or production logs in issues or pull requests.
