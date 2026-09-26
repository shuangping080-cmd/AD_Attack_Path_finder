# Evidence Model

This reference captures the project invariants that matter when modifying semantics, pathfinding, reports, or knowledge-base correlation.

## Evidence Boundary

The analyzer separates facts from interpretations:

- Raw or observed BloodHound edges are current graph facts.
- Semantic edges are derived interpretations of current facts.
- HTB knowledge-base chains are historical examples and structural hints.
- `knowledge-base/htb/structured/*.yaml` records are sanitized historical examples, not current target evidence.
- Missing information describes what must be collected before a stronger claim is made.

`confirmed_edges` must contain only raw or observed evidence from the current graph. Semantic findings and HTB historical edges must not be inserted into `confirmed_edges`.

## Path Status

Use these meanings consistently:

- `Confirmed Path`: every required edge is backed by current raw graph evidence and primitive preconditions are satisfied.
- `Candidate Path`: the current graph supports the structure, but exploitability still depends on stated assumptions.
- `Incomplete Path`: a plausible route exists, but one or more blocking facts are missing.

Do not equate "all displayed edges exist" with "attack is definitely exploitable." A raw relationship can still require preconditions, target properties, or downstream impact evidence.

## Relationship Versus Primitive

A BloodHound relationship is evidence. A primitive is an interpretation.

Example:

```text
HENRY --WriteSPN--> ALFRED
```

This can support:

- `SPNManipulation`: stronger, because `WriteSPN` directly evidences SPN write capability.
- `TargetedKerberoastCandidate`: still candidate/incomplete until ticket recovery and cracking are known.

Example:

```text
alice --GenericWrite--> svc_account
```

This is not automatically targeted Kerberoast. It requires object type, writable SPN precondition, and cracking outcome context.

## Knowledge Base Correlation

The knowledge base helps answer "which known HTB chain does this resemble?" It must not overwrite current graph facts.

Expected flow:

```text
Current graph prefix
  -> structural pattern match
  -> reviewed/normalized HTB examples
  -> candidate continuation and explanation
  -> missing information
```

Identity matching must preserve domain and machine context. Avoid reducing identities such as `HENRY@TOMBWATCHER.HTB` to bare `henry` in ways that pollute matches across labs.

## Missing Information

Represent missing information structurally, not as loose strings. Useful fields include:

- `question`
- `object`
- `reason`
- `suggested_source`
- `importance`
- `blocks_path`
- `relationship`
- `object_type`

Rank next investigations by whether they block a path, likely privilege impact, historical support, collection cost, and impacted path count.

## High-Risk Semantic Cases

Keep these conservative:

- `HighValue != Domain Admin`
- `AdminTo != DomainPrivilege`
- `MemberOf` into ordinary groups is not privilege gain by itself.
- `GenericWrite` can map to several candidates depending on target type and properties.
- `WriteDACL` and `WriteOwner` are control opportunities, not automatic completed escalation.
- `AllowedToAct` supports RBCD only when source control and service/SPN context are known.
- `CreateChild`, `GenericAll`, or `GenericWrite` over an OU can suggest BadSuccessor only with dMSA predecessor/successor evidence.
- SPN presence supports Kerberoast/Silver Ticket checks, but cracking/key compromise remains missing unless evidenced.

## Validation Checks

When path semantics change, include tests for:

- raw evidence staying in `confirmed_edges`
- semantic edges not double-scoring
- semantic self-loops not creating fake paths
- knowledge-only continuations staying candidate/incomplete
- missing information de-duplication and priority ranking
- identity matching across domains/labs
