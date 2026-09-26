# AD-Attack-Path-Finder Workflow

This reference covers routine project operation: importing graph data, running detectors, and interpreting CLI output.

## Setup

Use editable install during development:

```powershell
python -m pip install -e .
```

The CLI can also be run directly as a module:

```powershell
python -m adpath --help
```

## Import Data

Import a BloodHound zip, a directory of JSON files, or a single JSON file into a normalized graph directory:

```powershell
python -m adpath import path\to\vintage_bloodhound.zip -o data\vintage
python -m adpath import path\to\eighteen_bloodhound_export -o data\eighteen
```

Normalized output contains:

- `nodes.json`
- `edges.json`
- `graph.json`

The repository `.gitignore` excludes imported local graph data. Do not commit lab collection output unless the user explicitly asks and the data is safe to publish.

## Inspect Graph Content

List nodes and relationships:

```powershell
python -m adpath nodes -g data\vintage --type User
python -m adpath nodes -g data\vintage --type Group
python -m adpath nodes -g data\vintage --type Computer
python -m adpath edges -g data\vintage --relationship MemberOf
python -m adpath edges -g data\vintage --relationship AllowedToAct
```

When the CLI lacks a filter, inspect `nodes.json` and `edges.json` with structured PowerShell JSON parsing instead of ad hoc text matching.

## Run Detectors

Use detectors to inspect specific attack primitive families:

```powershell
python -m adpath kerberos -g data\vintage
python -m adpath delegation -g data\vintage
python -m adpath gmsa -g data\vintage
python -m adpath dmsa -g data\vintage
python -m adpath adcs -g data\vintage
python -m adpath ou -g data\vintage
python -m adpath gpo -g data\vintage
```

Detector findings are interpretations. A finding can have raw graph evidence, semantic evidence, missing information, and historical support. Do not describe a detector candidate as a confirmed compromise.

## Analyze From A Start Principal

Use `investigate` when the user provides a BloodHound zip or JSON directory plus an initial low-privilege account. It imports the graph if needed, runs the generic rule detectors, correlates structural matches against the public HTB knowledge base, ranks recommended paths, and emits an LLM/Hermes review prompt when the rule-based result is weak or incomplete:

```powershell
python -m adpath investigate path\to\vintage_bloodhound.zip --start "P.ROSA@VINTAGE.HTB" -o data\vintage --top-n 10 --markdown
python -m adpath investigate data\eighteen --start "ADAM.SCOTT@EIGHTEEN.HTB" --json
```

The LLM review section is a prompt/context block, not an external API call. Use it with Hermes or another local LLM to compare the current graph against `knowledge-base/htb/public-index.json`, `knowledge-base/htb/structured/`, `knowledge-base/attack-patterns/`, and `knowledge-base/pattern-cards/`. Keep the output evidence-safe: current graph facts and historical analogies must remain separate.

Use `candidate-path` for evidence-aware reasoning:

```powershell
python -m adpath candidate-path "P.ROSA@VINTAGE.HTB" -g data\vintage --max-depth 6 --top-n 10
python -m adpath candidate-path "C.NERI_ADM@VINTAGE.HTB" -g data\vintage --max-depth 5 --top-n 10 --show-evidence
python -m adpath candidate-path "ADAM.SCOTT@EIGHTEEN.HTB" -g data\eighteen --json
```

Use `privilege-path` for graph-first privilege-oriented paths:

```powershell
python -m adpath privilege-path "L.BIANCHI_ADM@VINTAGE.HTB" -g data\vintage --max-depth 5 --top-n 10
```

Use `analyze` for a compact combined view:

```powershell
python -m adpath analyze "C.NERI_ADM@VINTAGE.HTB" -g data\vintage --max-depth 4
```

## Real Lab Notes

Known validation datasets used in this repository:

- Certified: ACL and group membership path validation.
- Support: BloodHound.py compatibility and generic path validation.
- Forest: broader real-data graph stability.
- TombWatcher: `WriteSPN -> SPNManipulation -> TargetedKerberoastCandidate`.
- Vintage: gMSA/delegation/service-account style review, including `DELEGATEDADMINS --AllowedToAct--> DC01`.
- Eighteen: BadSuccessor and OU/control path reasoning.

Use these as regression anchors when changing parser or path semantics.
