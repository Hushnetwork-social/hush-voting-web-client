# Ubuntu Chromium + Orca Evidence Protocol — FEAT-002

**Feature**: FEAT-002 Authentication UX and State Machine
**Purpose**: Deterministic, redacted manual evidence for WCAG 2.2 AA screen-reader claims.
**Record**: `evidence/runs/ubuntu-orca-{timestamp}.md` (redacted; no credentials, no identity data).

---

## Fixed Tasks (deterministic, objective outcome codes)

| # | Task | Success measure | Outcome code |
|---|------|------------------|--------------|
| 1 | From a fresh install, identify and announce the three entry actions | Orca announces Create User, Restore Credential File, Restore Recovery Words in order | `ENTRY_COMPLETE` |
| 2 | From a locked user, announce the device-password field and Unlock action | Field label and button announced; no account/server-login language | `UNLOCK_ANNOUNCED` |
| 3 | After entering a wrong password, hear the combined privacy-safe error | Exact text: "The password is incorrect or the protected data is damaged." | `ERROR_ANNOUNCED` |
| 4 | Navigate to Forgot device password and announce recovery options | Recovery Words + Credential File offered; no remote reset claim | `RECOVERY_ANNOUNCED` |
| 5 | During removal, hear non-cancellable progress | Polite live region announces "Removing local data…" | `REMOVAL_PROGRESS` |

## Recording Rules

- Use only outcome codes above plus short redacted notes.
- NEVER record: passwords, mnemonics, keys, file contents, full addresses, election ids, raw console text.
- Screenshots use synthetic public identities only; redact any captured alias.

## Evidence Fields

```yaml
environment: ubuntu-chromium-orca
browser: chromium
screen_reader: orca
viewport: desktop-1920x1080
date: {timestamp}
tasks: {outcome-code list}
pass: {n}/{n}
notes: {redacted}
```
