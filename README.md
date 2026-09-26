# AD-Attack-Path-Finder

[中文说明](README.zh-CN.md)

AD-Attack-Path-Finder is an analysis-only toolkit for quickly extracting and reasoning about Active Directory attack paths from BloodHound.py / SharpHound collection data.

The goal is not to replace BloodHound. The goal is to cover the parts that BloodHound may not directly show as a single obvious route: semantic privilege interpretation, missing preconditions, HTB-style historical chain correlation, and LLM-assisted reasoning over a local knowledge base.

In short:

```text
BloodHound zip
    -> normalized AD graph
    -> rule-based relationship / primitive analysis
    -> candidate privilege paths
    -> HTB historical knowledge correlation
    -> LLM review prompt
    -> ranked recommended routes and conditions to verify
```

## Purpose

During HTB-style AD domain labs, a BloodHound graph often contains the raw relationships, but the final exploitation route is not always displayed directly. Some paths require semantic interpretation:

- `GenericWrite` may imply several different primitives depending on the target object.
- `WriteSPN` may suggest SPN manipulation and targeted Kerberoasting, but cracking and credential recovery are still separate conditions.
- `AdminTo` is host-local control, not domain privilege by itself.
- OU / GPO / dMSA / ADCS edges may be only preconditions until additional evidence is collected.
- Historical writeups may show a pattern, but they are not facts for the current graph.

This project tries to bridge that gap. It first uses deterministic rules already written in the codebase. If those rules do not find a strong route, it prepares structured context for an LLM such as Hermes to compare the current graph against the local HTB knowledge base and propose plausible routes with verification conditions.

## What It Does

- Imports BloodHound zip, JSON directory, or normalized graph data.
- Builds a normalized `nodes.json`, `edges.json`, and `graph.json`.
- Maps raw relationships to possible attack primitives.
- Distinguishes `Confirmed Path`, `Candidate Path`, and `Incomplete Path`.
- Keeps `Relationship != Primitive`.
- Keeps `HighValue != Domain Admin`.
- Keeps historical HTB examples separate from current graph evidence.
- Scores candidate paths by evidence quality, privilege gain, missing information, historical support, and path quality.
- Outputs next best investigations: what to collect or verify next.
- Generates a local LLM/Hermes review prompt when rule-based analysis is incomplete.

## Safety Scope

This repository is for authorized AD labs, HTB-style machines, security training, and permitted assessments.

It analyzes collected data only. It does not perform exploitation, password changes, RBCD writes, certificate enrollment, DCSync, lateral movement, Kerberoasting, or privilege escalation actions.

## Install

Use editable install during development:

```bash
python -m pip install -e .
```

Check the CLI:

```bash
python -m adpath --help
```

## One-Shot Investigation

Use `investigate` when you have a BloodHound zip and a known initial low-privilege account:

```bash
python -m adpath investigate path/to/bloodhound.zip --start "USER@DOMAIN.LOCAL" -o data/current --top-n 10 --markdown
```

Example:

```bash
python -m adpath investigate path/to/vintage_bloodhound.zip --start "P.ROSA@VINTAGE.HTB" -o data/vintage --top-n 10 --markdown
```

JSON output:

```bash
python -m adpath investigate path/to/bloodhound.zip --start "USER@DOMAIN.LOCAL" -o data/current --json
```

The command will:

1. Import the BloodHound data if needed.
2. Run ACL, Kerberos, delegation, gMSA, dMSA, ADCS, OU, and GPO detectors.
3. Build semantic edges for analysis without changing the raw graph.
4. Run candidate path search and privilege-oriented path search.
5. Match current graph structure against HTB historical knowledge.
6. Rank recommended paths.
7. List missing information and next best investigations.
8. Generate an LLM/Hermes prompt for knowledge-base-assisted review.

## LLM / Hermes Usage

The tool does not call an external LLM by itself. It emits a structured prompt in the `LLM Review` section.

When using Hermes on Kali or another local environment, provide:

- the BloodHound zip or normalized graph output;
- the start principal, for example `P.ROSA@VINTAGE.HTB`;
- the `investigate` output;
- the public knowledge files in this repository:
  - `knowledge-base/htb/public-index.json`
  - `knowledge-base/htb/structured/`
  - `knowledge-base/attack-patterns/`
  - `knowledge-base/pattern-cards/`

Suggested prompt:

```text
You are analyzing an authorized HTB-style AD lab.
Use the current BloodHound graph facts as evidence.
Use the HTB knowledge base only as historical reference.
Do not treat historical chains as confirmed facts.

Given this adpath investigate output, rank the most likely privilege routes from START_USER.
For each route, separate:
1. confirmed graph evidence
2. semantic interpretation
3. historical HTB analogies
4. missing conditions
5. next collection or validation steps

Return recommended paths by weight and explain what must be verified before the path can be considered workable.
```

## Common CLI Usage

Import only:

```bash
python -m adpath import path/to/bloodhound.zip -o data/current
```

Inspect graph content:

```bash
python -m adpath nodes -g data/current --type User
python -m adpath nodes -g data/current --type Group
python -m adpath nodes -g data/current --type Computer
python -m adpath edges -g data/current --relationship MemberOf
```

Run focused detectors:

```bash
python -m adpath kerberos -g data/current
python -m adpath delegation -g data/current
python -m adpath gmsa -g data/current
python -m adpath dmsa -g data/current
python -m adpath adcs -g data/current
python -m adpath ou -g data/current
python -m adpath gpo -g data/current
```

Run evidence-aware candidate path search:

```bash
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --max-depth 6 --top-n 10 --markdown
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --show-evidence
python -m adpath candidate-path "USER@DOMAIN.LOCAL" -g data/current --json
```

Run raw privilege-oriented graph search:

```bash
python -m adpath privilege-path "USER@DOMAIN.LOCAL" -g data/current --max-depth 5 --top-n 10
```

Find interesting foothold hypotheses:

```bash
python -m adpath foothold-candidates -g data/current --top-n 20 --markdown
```

Record analyst validation evidence locally:

```bash
python -m adpath evidence add -g data/current \
  --principal "HOST01$@DOMAIN.LOCAL" \
  --type credential_valid \
  --method kerberos_ldap \
  --note "authorized validation succeeded"
```

Expand from all controlled principals recorded in `evidence.json`:

```bash
python -m adpath candidate-path -g data/current --controlled --show-evidence
```

## Evidence Model

The project uses strict evidence boundaries:

- Raw BloodHound edge: current graph fact.
- Semantic primitive: interpretation of current graph evidence.
- Historical HTB chain: reference pattern only.
- Candidate path: plausible route that still needs conditions verified.
- Incomplete path: missing information blocks a stronger conclusion.

Example:

```text
Current graph:
alice --GenericWrite--> svc_sql

Semantic interpretation:
GenericWrite may enable identity control or SPN manipulation depending on object properties.

Historical support:
Similar HTB chains exist, but they do not confirm this environment.

Missing:
SPN state, writable attributes, service account host impact, sessions, credentials, ADCS/delegation context.
```

## Knowledge Base

The public repository contains a sanitized HTB historical knowledge layer:

- `knowledge-base/htb/public-index.json`
- `knowledge-base/htb/structured/*.yaml`
- `knowledge-base/attack-patterns/*.yaml`
- `knowledge-base/pattern-cards/*.yaml`
- `knowledge-base/primitives/*.yaml`
- `knowledge-base/relationships/*.yaml`

The public knowledge base stores structured chain summaries and reusable patterns. It does not include raw private writeup text, local BloodHound collections, or private SQLite data.

The intended knowledge flow is:

```text
raw writeup text, private/local
    -> domain exploitation section extraction
    -> chain / primitive / mechanism YAML
    -> reusable attack patterns
    -> skill and LLM-assisted reasoning
```

## Supported Analysis Areas

Current detector and path reasoning support includes:

- ACL: `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `ForceChangePassword`, `WriteSPN`
- Group membership and privileged group distinction
- Local admin versus domain privilege separation
- Kerberos: ASREPRoast, Kerberoast, TargetedKerberoast, Silver Ticket candidate, Golden Ticket candidate
- Delegation: unconstrained, constrained, RBCD, S4U-style reasoning
- gMSA and dMSA, including BadSuccessor-style candidate checks
- ADCS ESC-style template and CA signals
- OU and GPO control paths
- Pre-Windows 2000 compatible computer-account foothold hypotheses
- HTB historical pattern correlation without username reuse assumptions

## Repository Layout

```text
src/adpath/
  __main__.py, cli.py        CLI entry points, including import, investigate, candidate-path, and detectors
  investigate.py             one-shot BloodHound zip -> rules -> KB correlation -> LLM prompt workflow
  parsers/                   BloodHound JSON/zip parsing and normalization
  graph/                     in-memory AD graph model and normalized graph read/write helpers
  models/                    node, edge, primitive, evidence, missing-info, privilege, and path data models
  detectors/                 ACL, Kerberos, delegation, gMSA, dMSA, ADCS, OU, GPO, and privilege detectors
  pathfinder/                shortest path, privilege path, candidate path, path scoring, and explanations
  knowledge/                 YAML knowledge loading, primitive catalog, relationship catalog, pattern matching
  signal/                    foothold and interesting-object hypothesis engine
  collectors/                collector abstraction layer
  visualization/             placeholder for future visualization work

knowledge-base/
  relationships/             public relationship definitions and compatibility metadata
  primitives/                public attack primitive definitions, preconditions, and follow-up questions
  attack-patterns/           reusable structural attack patterns for graph matching
  pattern-cards/             higher-level interesting-signal and hypothesis cards
  htb/structured/            sanitized HTB historical chain summaries
  htb/public-index.json      public index of structured HTB knowledge records
  schemas/                   YAML schemas for knowledge records

skill/ad-attack-path/
  SKILL.md                   Codex skill entry point for using and evolving this project
  references/                workflow, evidence model, and historical knowledge guidance
  agents/                    skill metadata

tests/                       regression tests for parser, semantics, paths, knowledge, reports, and signals
scripts/                     public-safe export and validation helpers
docs/                        non-sensitive validation notes and project checklists
data/                        ignored local graph workspace; only .gitkeep placeholders are tracked
web/                         placeholder for future local visualization assets
references/                  public reference notes
```

Local BloodHound data, analyst evidence, and private SQLite knowledge-base files should stay out of Git.

## Project Direction

The long-term direction is to make AD lab reasoning faster:

1. Use BloodHound as the graph evidence source.
2. Use deterministic rules for known relationships and primitives.
3. Use the local knowledge base to recognize historical chain shapes.
4. Use an LLM to reason over gaps and suggest likely next investigations.
5. Return concise, weighted, evidence-safe recommendations.

The output should help answer:

```text
I have this initial low-privileged account and this BloodHound zip.
What routes are confirmed?
What routes are plausible?
What information is missing?
Which route should I test next?
Which HTB chains look structurally similar?
```
