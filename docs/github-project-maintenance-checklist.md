# GitHub Project Maintenance Checklist

## Goal

Keep the public GitHub repository focused on the reusable AD attack path analysis tool.

The repository should contain code, schemas, tests, documentation, and safe examples. Local writeups, private SQLite data, collected BloodHound exports, and reviewed case notes should stay outside GitHub unless they are sanitized fixtures.

Core boundary:

```text
GitHub repo = tool + schema + examples
Local knowledge base = writeups + reviewed chains + private case evidence
```

## 1. Repository Boundary

- [x] Define which directories are public-safe.
- [x] Define which directories are local-only.
- [x] Keep source code in `src/adpath/`.
- [x] Keep tests in `tests/`.
- [x] Keep public docs in `docs/`.
- [x] Keep reusable skill instructions in `skill/`.
- [x] Keep public schema examples, but not private reviewed machine data.
- [x] Move private writeups and raw BloodHound data out of the Git-tracked tree.
- [x] Add local-only paths to `.gitignore`.

## 2. Public-Safe Knowledge Assets

- [x] Keep generic relationship definitions.
- [x] Keep generic primitive definitions.
- [x] Keep generic pattern-card schema.
- [x] Keep sanitized sample pattern cards.
- [x] Keep toy/sample machine records only if they contain no copied WP text or sensitive data.
- [x] Replace real HTB writeup excerpts with short synthetic examples when publishing.
- [x] Mark public examples as fixtures, not real evidence.

## 3. Local-Only Assets To Exclude

- [x] Exclude full WP source files.
- [x] Exclude extracted WP text.
- [x] Exclude reviewed real machine chains if they include WP-derived evidence.
- [x] Exclude raw BloodHound JSON/ZIP collections.
- [x] Exclude SQLite knowledge databases.
- [x] Exclude analyst notes.
- [x] Exclude generated cache directories.
- [x] Exclude temporary report outputs.

## 4. Cleanup Pass

- [x] Review `data/` and decide whether each file is fixture or local-only.
- [x] Review `writeups/` and move real WP content to the local knowledge workspace.
- [x] Review `knowledge-base/htb/` and keep only sanitized templates in GitHub.
- [ ] Review `references/` and keep only allowed public references.
- [ ] Review `scripts/` and remove stale one-off scripts.
- [ ] Review `web/` and decide whether it is part of the product roadmap.
- [ ] Remove generated caches from the working tree.
- [x] Ensure no credentials, hashes, private notes, or copied article bodies are tracked.

## 5. Engineering Hardening

- [ ] Keep CLI commands stable and documented.
- [ ] Keep schema validation runnable from the repository.
- [ ] Keep all public tests passing.
- [ ] Add fixture-based tests for pattern matching.
- [ ] Add fixture-based tests for relationship-to-primitive reasoning.
- [ ] Add fixture-based tests for route scoring.
- [ ] Add fixture-based tests for local-KB adapter behavior without requiring the real DB.
- [ ] Keep the local SQLite backend optional at runtime.

## 6. Documentation

- [ ] Update README with the public/private boundary.
- [ ] Document how to run the analyzer without a local KB.
- [ ] Document how to point the analyzer at a local SQLite KB.
- [ ] Document that writeup knowledge is historical support, not confirmed graph evidence.
- [ ] Document that `Relationship != Primitive`.
- [ ] Document that `HighValue != Domain Admin`.
- [ ] Document confirmed/candidate/incomplete path status.
- [ ] Document the intended role of skills.

## 7. Skill Packaging

- [ ] Keep skill instructions generic.
- [ ] Put analysis methodology into `skill/`.
- [ ] Do not put private machine chains directly into skill instructions.
- [ ] Let skills call or describe the local KB retrieval flow.
- [ ] Include rules for evidence boundaries.
- [ ] Include rules for missing-information ranking.
- [ ] Include route explanation templates.

## 8. Git Hygiene

- [ ] Run `git status --short` before staging.
- [ ] Stage only public-safe files.
- [ ] Review staged diff before commit.
- [ ] Run tests before commit.
- [ ] Run lint on touched files before commit.
- [ ] Do not commit local SQLite DB files.
- [ ] Do not commit raw WP or BloodHound export files.
- [ ] Commit cleanup separately from feature work when possible.

## 9. Completion Criteria

- [ ] GitHub repo can be cloned and tested without local private data.
- [ ] Public fixtures demonstrate behavior without leaking real writeup content.
- [ ] Local-only data paths are ignored by Git.
- [ ] README clearly explains the local KB boundary.
- [ ] Skill instructions remain reusable and case-agnostic.
- [ ] The code can optionally enrich analysis from a local SQLite KB.
