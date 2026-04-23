# @omnituum/pqc-shared — Knowledge

**Date:** 2026-04-23
**Module:** pqc-shared
**Registry entry:** `governance/module-system/MODULE_INDEX.json` → `modules[]` where `module == 'pqc-shared'`
**Canonical-4 root:** `libs/Omnituum/pqc-shared/package-docs/`
**Prefix:** `**PQC-##**` — see DOC_STANDARD § Module-Scoped ID Grammar.

---

## Deployment / Runtime State

Authoritative source: `libs/Omnituum/pqc-shared/package-docs/PQC_SHARED_OVERVIEW.md` § Where It Sits.

Snapshot rule: bump the `Date:` header above and re-upload this file to ChatGPT whenever the OVERVIEW's deployment details change.

## Directory Layout

Authoritative source: filesystem state at `libs/Omnituum/pqc-shared/`. Capture via `tree libs/Omnituum/pqc-shared -L 3` (or `ls -R`) and paste under this section at refresh time. Do not duplicate inline here — re-render on refresh.

## Shared Utilities

Authoritative source: `libs/Omnituum/pqc-shared/package.json` (or `pyproject.toml` / `Cargo.toml` per language) dependencies + `libs/Omnituum/pqc-shared/package-docs/PQC_SHARED_OVERVIEW.md` § Where It Sits > Depends on.

## Issues / Tasks

**Authoritative file:** `libs/Omnituum/pqc-shared/package-docs/GAPS_AND_TASKS.md`.

**Refresh workflow:** when the GAPS file changes, bump the `Date:` header above and re-upload this knowledge file to ChatGPT. No changes to the instructions file required.

**Count authority:** the GAPS `## Status Summary` block (`Tracked`, `Complete`, `Open` bullets) is parsed by DS-01 at `sites/loggie-docs-site`. Do not override those counts from this knowledge file.

## Patterns / Standards

- `governance/standards/package-docs/reference/DOC_STANDARD.md` — canonical workspace standard (DOC_STANDARD § Canonical Contract, § GAPS_AND_TASKS Schema, § Custom GPT Documents, § Freshness Policy, § Module Locations).
- `governance/standards/package-docs/reference/GITIGNORE_BASELINE.md` — repo-hygiene baseline.
- Prefix grammar: `**PQC-##**` where `##` is zero-padded as required; optional lowercase suffix allowed per § Module-Scoped ID Grammar.

## Cross-Dependencies

Authoritative: `governance/module-system/MODULE_INDEX.json` entry for `pqc-shared` — fields `blocked_by` (this module needs these first) + `enables` (these modules need this module). Re-read on refresh.

## Valid Issue IDs

Shape: `**PQC-##**` (optionally with lowercase suffix: `**PQC-##a**`).

Refuse any ID shape that doesn't match. In particular:

- IDs from other modules' prefixes (cross-module pointers are tracked, not owned here).
- Unregistered prefixes (see DOC_STANDARD § Registered Prefixes).
- Numeric-only or prefix-only forms.

## Refresh Workflow

Bump this file's `Date:` header and re-upload to ChatGPT when any of the following changes:

- The module's OVERVIEW (deployment / runtime state).
- The module's GAPS_AND_TASKS.md (issue list, counts, or priority order).
- The module's `package.json` / language manifest (dependency surface).
- The MODULE_INDEX entry (registry fields — `layer`, `priority`, `blocked_by`, `enables`, `status`).

No changes to the instructions file are required at refresh time — the instructions reference this file by name, not by content.
