---
name: Bug report
about: Report a defect in the phptopwn sensor's detection, storage, decoy or packaging
labels: bug
---

## Summary

<!-- One or two sentences: what happened, and what you expected instead. -->

## Environment

- phptopwn version: <!-- output of `phptopwn --version` or image tag -->
- Deployment: <!-- pip / docker compose / systemd -->
- Python / OS: <!-- e.g. 3.12, Debian 12 -->

## Steps to reproduce

<!-- Minimal, replayable steps. Include the exact request (curl line), the
     phptopwn.toml / env overrides involved, and the relevant startup log. -->

## Observed behaviour

<!-- Paste the log line / record / exposition output (redact IPs if needed). -->

## Expected behaviour

<!-- What the sensor should have done instead, citing the README or
     docs/CONFIG.md section if it contradicts current docs. -->

## Safety note

If the defect involves storing or serving executable content, state exactly
where the file landed and how it would be reached by an interpreter — that
class of report is treated as high priority.
