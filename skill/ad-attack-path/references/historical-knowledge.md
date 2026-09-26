# Historical Knowledge Retrieval

Use this reference when a task asks to compare a current graph or finding with
known HTB-style AD attack chains.

## Public Knowledge Files

The GitHub-safe historical knowledge base lives in:

```text
knowledge-base/htb/public-index.json
knowledge-base/htb/structured/*.yaml
```

These files are sanitized exports from the local SQLite knowledge base. They
contain structural chain knowledge only:

- machine names
- source URLs
- entities used in historical chain steps
- relationships
- primitives
- ordered chain steps
- preconditions
- missing information
- evidence-boundary labels

They do not contain raw writeup text, local markdown paths, local SQLite data,
raw BloodHound exports, passwords, hashes, or private analyst notes.

## Retrieval Workflow

1. Read `knowledge-base/htb/public-index.json` first.
2. Match by structure, relationship, primitive, and object type.
3. Open only the relevant machine YAML files from `knowledge-base/htb/structured/`.
4. Use historical chains as pattern support and explanation context.
5. Keep current graph facts separate from historical examples.

Useful matching keys:

- `relationships`
- `primitives`
- `attack_chain[].relationship`
- `attack_chain[].primitive`
- `attack_chain[].source.type`
- `attack_chain[].target.type`
- `attack_chain[].missing_information`

## Evidence Boundary

Historical records are never current-environment proof.

Use them to say:

```text
This resembles the Pirate chain:
Pre2K computer password -> gMSA read -> PetitPotam/relay -> RBCD -> S4U.
```

Do not say:

```text
The current graph is confirmed exploitable because Pirate had this chain.
```

For current findings:

- raw BloodHound edge = current evidence
- primitive = interpretation
- historical YAML = prior example / pattern support
- missing information = what to collect next

## Exporting Updated Knowledge

When the local SQLite KB has been curated further, regenerate the public export:

```powershell
python scripts\export_public_knowledge.py
```

Review the diff before committing. The export must not introduce raw writeup
text, local paths, SQLite files, or BloodHound collection data.
