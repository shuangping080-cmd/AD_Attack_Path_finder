---
name: ad-attack-path
description: Analyze and evolve the AD-Attack-Path-Finder project, including BloodHound imports, candidate path review, evidence-safe semantic analysis, and HTB knowledge-base correlation.
metadata:
  short-description: Work on AD-Attack-Path-Finder
---

# AD Attack Path

Use this skill when working inside the AD-Attack-Path-Finder repository or when analyzing BloodHound.py / SharpHound data with its `adpath` CLI.

The project is an analysis layer for authorized AD labs and assessments. It imports BloodHound-style data, maps raw relationships to attack primitives, correlates current graph evidence with reviewed HTB knowledge, and explains confirmed, candidate, and incomplete paths. It must not perform exploitation, password changes, RBCD writes, certificate enrollment, DCSync, lateral movement, or any other live attack action.

## Core Rules

- Treat BloodHound graph edges as facts and semantic primitives as interpretations.
- Never promote knowledge-base examples or semantic edges into confirmed graph evidence.
- Explain missing information instead of overclaiming exploitability.
- Prefer `investigate` for a full zip-to-report workflow, `candidate-path` for focused evidence-aware reasoning, and `privilege-path` for raw privilege-oriented graph paths.
- Keep source changes scoped and validate with `pytest`, `ruff`, and candidate-path safety checks when path semantics are touched.

## Common Workflows

- For importing BloodHound zip or JSON data, running detectors, and reviewing paths, read [workflow.md](references/workflow.md).
- For changes involving confirmed/candidate/incomplete status, semantic edges, missing information, or HTB correlation, read [evidence-model.md](references/evidence-model.md).
- For comparing a current graph or finding to known HTB-style chains, read [historical-knowledge.md](references/historical-knowledge.md).

## Repository Landmarks

- CLI entry point: `src/adpath/cli.py`
- BloodHound parser: `src/adpath/parsers/bloodhound_parser.py`
- Primitive detectors: `src/adpath/detectors/`
- Candidate path engine: `src/adpath/pathfinder/candidate_path.py`
- Knowledge loading and matching: `src/adpath/knowledge/`
- Report shaping and investigation ranking: `src/adpath/reports.py`
- Knowledge base: `knowledge-base/`
- Public historical chain index: `knowledge-base/htb/public-index.json`
- Public historical chain records: `knowledge-base/htb/structured/`
- Tests: `tests/`
- Candidate path invariant validator: `scripts/validate_candidate_paths.py`

## Validation

After modifying analysis behavior, run the narrow relevant tests first, then the full suite when feasible:

```powershell
python -m pytest
python -m ruff check src tests scripts
```

For graph-specific work, also validate a representative candidate path:

```powershell
python scripts\validate_candidate_paths.py "ADAM.SCOTT@EIGHTEEN.HTB" -g data\eighteen
python scripts\validate_candidate_paths.py "C.NERI_ADM@VINTAGE.HTB" -g data\vintage --max-depth 5 --top-n 10
```
