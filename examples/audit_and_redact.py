from pydotenvcage import audit_dotenv, redact_dotenv

source = "\n".join([
    "# local application settings",
    "PORT=8080",
    "NODE_OPTIONS=--require=evil",
])

report = audit_dotenv(source, context="committed")
for finding in report.findings:
    print(finding.line, finding.severity, finding.code, finding.key or "-")

print(redact_dotenv(source))
