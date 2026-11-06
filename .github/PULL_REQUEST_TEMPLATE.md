# Pull request

## What changed

<!-- Modules touched and why. Keep one concern per PR. -->

## How it was verified

<!-- CI runs the gates below automatically; describe anything CI cannot see
     (manual decoy requests, redeploy, retention behaviour on real files).

- [ ] `ruff check phptopwn tests` passes
- [ ] `mypy phptopwn` passes
- [ ] `python -m coverage run --branch --source=phptopwn -m pytest` then
      `python -m coverage report --fail-under=85` passes with no coverage regressions
- [ ] `python3 tests/smoke_test.py` passes end to end
- [ ] Docs updated when behaviour, config or metrics changed
      (README and/or docs/CONFIG.md, CHANGELOG under [Unreleased])
-->

## Safety checklist

<!-- The honeypot must never execute or route attacker bytes to an
     interpreter, and quarantined captures must stay neutralized.

- [ ] No change lets attacker-controlled content reach `eval`, `exec`,
      `subprocess`, PHP or any other interpreter
- [ ] Capture files still land under `captured_payloads/` with neutralized
      names (or the relaxation is explicitly documented as opt-in)
- [ ] New log fields stay free of unbounded attacker bytes (probe-cap aware)
-->

## Default config compatibility

<!-- List any TOML/env change, including renamed or added fields, validation
     bound changes and migration notes for operators upgrading. -->
