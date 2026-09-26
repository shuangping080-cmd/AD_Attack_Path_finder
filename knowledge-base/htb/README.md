# HTB Knowledge Records

This public repository keeps the machine-record template, generic schemas, and
sanitized historical HTB chain records.

Raw writeup text, local analyst notes, local SQLite databases, and
BloodHound-derived collection evidence are local-only.

Sanitized historical records are exported from the local SQLite knowledge base
with:

```powershell
python scripts\export_public_knowledge.py
```

The export intentionally includes only structural knowledge:

- machine name
- source URLs
- entities used in chain steps
- relationships
- primitives
- ordered historical chain steps
- preconditions and missing information
- evidence boundary labels

It does not include raw writeup excerpts, local markdown paths, local SQLite
files, or raw BloodHound exports.

Public-safe content belongs in:

- `knowledge-base/relationships/`
- `knowledge-base/primitives/`
- `knowledge-base/pattern-cards/`
- `knowledge-base/schemas/`
- `knowledge-base/htb/structured/`
- `knowledge-base/htb/public-index.json`

Local-only content belongs outside Git or under ignored paths:

- `writeups/`
- `knowledge-base/htb/raw-writeups/`
- `knowledge-base/htb/extracted/`
- `knowledge-base/htb/normalized/`
- `knowledge-base/htb/reviewed/`
- `knowledge-base/htb/reviewed-candidates/`
- local SQLite database files

`knowledge-base/htb/structured/*.yaml` records are historical examples only.
They are useful for pattern matching and explanation, but they must never be
treated as confirmed evidence for a current target graph.
