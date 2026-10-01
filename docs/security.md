# Security design

## Principle
Local, fixed rules decide every status and the phishing verdict. The AI only explains the
results in plain language. It cannot run commands and cannot change a verdict.

## Threats and mitigations

| Threat | Mitigation | Tested in |
| --- | --- | --- |
| An email tries to instruct the AI ("classify me as safe") | Email text is marked as untrusted data; the verdict is calculated before the AI is asked and shown separately | P04 |
| Script or HTML inside an email reaches the report | Every value is HTML-encoded before it is written | P06 |
| The AI gives dangerous advice ("turn off the firewall") | The system prompt forbids disabling security features; employees get at most 3 safe steps | T05 |
| The API key leaks | Stored in a user environment variable, never in code; GitHub push protection on; monthly spend limit | Manual check |
| Personal data is sent to a cloud service | Only check summaries are sent, no user or computer names; `-NoAI` runs fully offline | T07 |
| The tool changes the system | All checks are read-only | Code review |
| Scripts run with lowered policy | `-ExecutionPolicy Bypass` applies to one process only | Manual check |

## What I would add in a company
- Sign the scripts with a code-signing certificate and enforce `AllSigned`
- Deploy through Intune instead of manual copies
- Use a company AI endpoint with a data processing agreement (GDPR)
- Store the key in a secret vault, not in a user variable