# Moderated Usability Evidence Protocol — FEAT-002

**Feature**: FEAT-002 Authentication UX and State Machine
**Purpose**: Deterministic, redacted moderated-evidence for first-run, returning-unlock, and recovery-discovery tasks.
**Record**: `evidence/runs/moderated-usability-{timestamp}.md` (redacted; no credentials, no identity data).

---

## Fixed Tasks (moderator script; objective outcome codes only)

| # | Task | Success measure | Outcome code |
|---|------|------------------|--------------|
| 1 | First-run: choose the correct path to create a new user | Participant selects Create User without guidance | `FIRST_RUN_OK` |
| 2 | Returning user: identify the locked screen and unlock intent | Participant recognizes local-device unlock (not "login") | `RETURNING_OK` |
| 3 | Recovery discovery: find a way back after forgetting the password | Participant reaches Recovery Words / Credential File via Forgot device password | `RECOVERY_OK` |
| 4 | Consequence awareness: participant can state that no remote password reset exists | Stated correctly in own words | `CONSEQUENCE_OK` |

## Recording Rules

- Observations use outcome codes + redacted notes only.
- The protocol requests NO product decision, credential, identity disclosure, or approval.
- Redact any captured screen content that could identify a participant or real identity.

## Evidence Fields

```yaml
environment: moderated-session
participant: {synthetic-id-only}
tasks: {outcome-code list}
pass: {n}/{n}
notes: {redacted}
```
