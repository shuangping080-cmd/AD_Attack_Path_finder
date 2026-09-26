# AD Attack Path Knowledge Base

This public knowledge base is not a writeup collection.

Its purpose is to convert real-world-like Active Directory attack chains into normalized samples that can support:

- Relationship modeling
- Attack primitive mapping
- Multi-stage privilege transitions
- Candidate path discovery
- Missing information prompts
- BloodHound semantic gap analysis

Raw writeups, copied article text, reviewed machine chains, analyst notes, and BloodHound-derived evidence are local-only.

The public repository keeps generic schemas, relationships, primitives, and pattern cards. Machine-specific records should come from a local SQLite knowledge base or ignored local directories.

## Workflow

```text
Local Raw Writeup
-> Text extraction
-> Entity extraction
-> Relationship extraction
-> Attack primitive extraction
-> Attack chain ordering
-> Normalization
-> Validation
-> Local SQLite records
-> Optional sanitized fixtures
```

## Directories

- `htb/`: public template and local-only boundary documentation
- `primitives/`: primitive dictionary
- `relationships/`: relationship dictionary
- `attack-patterns/`: reusable pattern templates observed across machines
- `pattern-cards/`: public-safe structural patterns and reasoning prompts
- `schemas/`: schema documentation and templates

## Evidence Rule

Every important relationship, primitive, chain step, and semantic gap in the local KB must include evidence that points back to a local source record. Unknown facts must stay unknown. Do not infer missing data just to make a path complete.
