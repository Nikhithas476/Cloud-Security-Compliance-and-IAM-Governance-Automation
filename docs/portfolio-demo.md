# Portfolio demonstration

Run `.venv\Scripts\python.exe scripts/portfolio_demo.py`. It uses actual orchestration, compliance,
risk, reporting, alert and remediation components with mocked AWS/Azure results. It shows both scans,
normalized findings, scores, reports, a critical alert, explicit approval, verified remediation, and
a second improved scan. Sanitized artifacts go to ignored `demo-output/`.

For a live lab, follow `infrastructure/demo/README.md` only in disposable isolated environments.
AWS cannot backdate access keys, so stale age is mocked instead of storing a real secret in Terraform
state. Show: plan → first scan/report → approval → mutation → verification → second scan/report →
destroy plan.

Interview narrative: cloud adapters normalize different APIs; rules/risk remain provider-neutral;
partial failure preserves evidence; scan identities cannot mutate; approvals are exact and
non-replayable; verification and audit close the loop; CI enforces the demonstrated controls.
