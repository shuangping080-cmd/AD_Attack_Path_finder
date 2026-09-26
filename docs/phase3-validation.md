# Phase 3 Validation Notes

Phase 3 validates that the analyzer can ingest real BloodHound.py output and run advanced primitive detectors without treating every relationship as a confirmed exploit.

## Real BloodHound Data

Validated local datasets:

| Dataset | Input | Nodes | Edges | Result |
| --- | --- | ---: | ---: | --- |
| Certified | local Certified BloodHound export | 87 | 591 | Imported without parser warnings |
| Support | local Support BloodHound export | 98 | 674 | Imported without parser warnings |
| Forest | local Forest BloodHound export | 147 | 1310 | Imported without parser warnings |

The parser now accepts `containers` files and emits `Container` nodes, so Certified no longer reports unsupported container data.

## Detector Smoke Results

The unified detector pipeline completed across all three imported graphs.

Observed Phase 3 primitive families include:

- Kerberos candidates: `Kerberoast`, `ASREPRoast`, `TargetedKerberoast`
- OU / GPO semantics: `OUContainsObject`, `OUControl`, `GPOLink`, `GPOControl`
- dMSA precondition analysis: `BadSuccessor` as `incomplete`
- Existing ACL semantics still feed the same graph and path layer

## Status Rules

- `confirmed`: graph evidence is direct relationship evidence, such as containment or managed-password read.
- `candidate`: evidence suggests a possible primitive but still needs context, such as template settings, target services, or downstream privileges.
- `incomplete`: core preconditions are missing. Examples: `SilverTicketCandidate` without service key compromise, and `BadSuccessor` without dMSA predecessor/successor evidence.

## Commands Used

```bash
python -m adpath import path/to/certified_bloodhound_export -o data/phase3-validation/Certified
python -m adpath import path/to/support_bloodhound.zip -o data/phase3-validation/Support
python -m adpath import path/to/forest_bloodhound.zip -o data/phase3-validation/Forest
python -m pytest
```

## Current Limitations

Phase 3 is still analysis-only. It does not perform certificate enrollment, Kerberos ticket requests, RBCD writes, password reads, DCSync, lateral movement, or exploitation.
