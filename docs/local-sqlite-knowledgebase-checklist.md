# Local SQLite Knowledge Base Checklist

## Goal

Build a local-only knowledge base for AD attack path reasoning.

The local KB should preserve original writeup evidence, extract domain-relevant attack chains, classify mechanisms and knowledge points, and provide structured material for future LLM-assisted analysis.

Core model:

```text
WP raw source
↓
Domain attack chain extract
↓
Mechanism / primitive / relationship knowledge
↓
Pattern and taxonomy layer
↓
Skill-guided LLM reasoning
```

## 1. Local Storage Boundary

- [ ] Create a local KB workspace outside the Git-tracked public repo, or under an ignored path.
- [ ] Store SQLite database files locally only.
- [ ] Store raw WP text locally only.
- [ ] Store copied article excerpts locally only.
- [ ] Store private analyst notes locally only.
- [ ] Store raw BloodHound collections locally only.
- [ ] Add local KB paths to `.gitignore`.
- [ ] Keep only schemas, adapters, and sanitized fixtures in GitHub.

## 2. SQLite Schema Foundation

- [ ] Create `sources` table for WP pages, PDFs, official docs, blogs, and tool docs.
- [ ] Create `machines` table for HTB/lab targets.
- [ ] Create `domains` table for AD domain metadata.
- [ ] Create `entities` table for users, groups, computers, OUs, GPOs, CAs, templates, service accounts, gMSA, dMSA.
- [ ] Create `relationships` table for graph-visible or WP-observed relationships.
- [ ] Create `chain_steps` table for ordered attack chain steps.
- [ ] Create `primitives` table for attack primitives.
- [ ] Create `mechanisms` table for reusable AD mechanisms.
- [ ] Create `pattern_cards` table for structural patterns.
- [ ] Create `tags` table.
- [ ] Create many-to-many tag mapping tables.
- [ ] Create `evidence_items` table.
- [ ] Create `missing_information` table.
- [ ] Create `validation_methods` table.
- [ ] Create `historical_examples` table.

## 3. Raw Source Layer

- [ ] Import WP original text or local extracted text.
- [ ] Store source URL, author, title, machine, and local path.
- [ ] Store content hash for deduplication.
- [ ] Store collection timestamp.
- [ ] Mark source type:
  - [ ] `writeup`
  - [ ] `official_doc`
  - [ ] `tool_doc`
  - [ ] `blog`
  - [ ] `bloodhound_export`
- [ ] Mark trust level.
- [ ] Preserve raw evidence without rewriting it as fact.

## 4. Domain Chain Extraction Layer

- [ ] Read the selected WP before writing machine-specific records.
- [ ] Extract only domain/AD-relevant sections first.
- [ ] Preserve enough initial access context to explain the starting identity.
- [ ] Extract ordered attack chain steps.
- [ ] Extract source principal.
- [ ] Extract relationship.
- [ ] Extract target object.
- [ ] Extract primitive.
- [ ] Extract result.
- [ ] Extract required preconditions.
- [ ] Extract missing evidence.
- [ ] Extract validation commands if present.
- [ ] Mark whether each step is BloodHound-visible.
- [ ] Mark whether each step is external host/tool action.
- [ ] Mark confidence for each step.

## 5. Evidence Boundary

- [ ] Separate `fact`, `interpretation`, `hypothesis`, and `rule`.
- [ ] Store BloodHound edges as graph evidence.
- [ ] Store WP claims as historical evidence.
- [ ] Store inferred techniques as interpretation.
- [ ] Store validation needs as missing information.
- [ ] Never promote WP-derived knowledge into confirmed current-graph evidence.
- [ ] Require raw/observed current evidence for `confirmed` status.
- [ ] Keep candidate and incomplete paths explicit.

## 6. Mechanism Knowledge Layer

- [ ] Extract reusable mechanisms from multiple machines.
- [ ] Link mechanisms to relationships.
- [ ] Link mechanisms to primitives.
- [ ] Link mechanisms to required object types.
- [ ] Link mechanisms to required properties.
- [ ] Link mechanisms to preconditions.
- [ ] Link mechanisms to false-positive conditions.
- [ ] Link mechanisms to validation methods.
- [ ] Link mechanisms to historical examples.
- [ ] Track affected AD/Windows/BloodHound versions when relevant.

## 7. Pattern Card Layer

- [ ] Create pattern cards from repeated chain structures.
- [ ] Match by structure, not historical username.
- [ ] Include source object type.
- [ ] Include target object type.
- [ ] Include relationship indicators.
- [ ] Include property indicators.
- [ ] Include missing information.
- [ ] Include next-best validation steps.
- [ ] Include historical machines that used the pattern.
- [ ] Include confidence and collection cost.
- [ ] Include common false positives.

## 8. Tag And Taxonomy Layer

- [ ] Use tags instead of single-category folders.
- [ ] Add tactic tags:
  - [ ] `CredentialAccess`
  - [ ] `PrivilegeEscalation`
  - [ ] `LateralMovement`
  - [ ] `Persistence`
- [ ] Add AD mechanism tags:
  - [ ] `ACLAbuse`
  - [ ] `Kerberos`
  - [ ] `Delegation`
  - [ ] `gMSA`
  - [ ] `dMSA`
  - [ ] `ADCS`
  - [ ] `OUControl`
  - [ ] `GPOControl`
  - [ ] `LocalAdmin`
  - [ ] `Trusts`
- [ ] Add reasoning tags:
  - [ ] `BloodHoundVisible`
  - [ ] `BloodHoundGap`
  - [ ] `ExternalValidation`
  - [ ] `CandidateOnly`
  - [ ] `ConfirmedOnlyWithEvidence`
- [ ] Add risk tags:
  - [ ] `IdentityControl`
  - [ ] `CredentialExposure`
  - [ ] `TierCrossing`
  - [ ] `HighValueImpact`

## 9. Initial Machine Curation Queue

- [ ] Vintage:
  - [ ] Pre-Windows 2000 Compatible Access chain.
  - [ ] Computer password hypothesis.
  - [ ] gMSA password read path.
  - [ ] Targeted Kerberoast continuation.
- [ ] TombWatcher:
  - [ ] WriteSPN to SPN manipulation.
  - [ ] Targeted Kerberoast candidate.
  - [ ] Missing credential recovery outcome.
- [ ] Eighteen:
  - [ ] OU CreateChild.
  - [ ] BadSuccessor/dMSA mechanism.
  - [ ] BloodHound collection gap.
- [ ] Escape:
  - [ ] ADCS chain.
  - [ ] ESC mechanism tags.
- [ ] Certified:
  - [ ] Validate existing BloodHound graph against expected chain.
- [ ] Support:
  - [ ] Validate current parser and primitive matching.
- [ ] Forest:
  - [ ] Validate privilege path and high-value classification.

## 10. LLM Retrieval Design

- [ ] Retrieve graph facts first.
- [ ] Retrieve matching pattern cards second.
- [ ] Retrieve historical examples third.
- [ ] Retrieve raw WP evidence only when needed.
- [ ] Feed the LLM structured records, not unrestricted raw dumps.
- [ ] Give the LLM explicit evidence-boundary labels.
- [ ] Ask the LLM to explain, rank, and propose validation.
- [ ] Do not allow the LLM to mark current paths confirmed without current evidence.

## 11. Skill Integration

- [ ] Put general reasoning rules into skill instructions.
- [ ] Put output templates into skill instructions.
- [ ] Put evidence-boundary rules into skill instructions.
- [ ] Put missing-information ranking rules into skill instructions.
- [ ] Put database query workflow into skill instructions.
- [ ] Do not put full private WP content into skills.
- [ ] Do not put every machine chain directly into skills.
- [ ] Let skills consume retrieved KB records.

## 12. Tool Integration

- [ ] Add local SQLite adapter.
- [ ] Add KB import command.
- [ ] Add KB validate command.
- [ ] Add KB search command.
- [ ] Add KB pattern-match command.
- [ ] Add KB machine-chain command.
- [ ] Add KB evidence lookup command.
- [ ] Add graph-to-KB correlation command.
- [ ] Add migration/version table.
- [ ] Add backup/export command for local use.

## 13. Quality Control

- [ ] Require reviewed status before a machine chain affects ranking.
- [ ] Track extraction status:
  - [ ] `raw_imported`
  - [ ] `domain_extracted`
  - [ ] `normalized`
  - [ ] `reviewed`
  - [ ] `deprecated`
- [ ] Track source confidence.
- [ ] Track reviewer.
- [ ] Track last reviewed time.
- [ ] Add duplicate source detection.
- [ ] Add duplicate chain detection.
- [ ] Add schema validation.
- [ ] Add tests with a temporary SQLite DB.

## 14. Completion Criteria

- [ ] Local SQLite KB stores raw WP evidence outside GitHub.
- [ ] At least three machines have reviewed domain-chain records.
- [ ] At least three reusable mechanisms are extracted from those machines.
- [ ] Pattern matching works by graph structure, not username.
- [ ] Analyzer can enrich current graph output with historical examples.
- [ ] Analyzer can list missing information and next validation steps.
- [ ] Skills contain stable reasoning rules without private raw data.
- [ ] GitHub repository remains cloneable and testable without the local KB.
