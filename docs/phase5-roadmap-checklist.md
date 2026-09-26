# Phase 5+ Roadmap Checklist

## Goal

Upgrade AD-Attack-Path-Finder from a graph path analyzer into a multi-route AD reasoning assistant.

The tool should not only answer "how can source A reach Domain Admins?", but also:

- identify interesting objects in the current graph
- explain why they matter in AD terms
- correlate them with historical HTB/writeup patterns
- generate conservative validation hypotheses
- import validation evidence
- expand paths from validated identities
- rank multiple routes by evidence, value, cost, and uncertainty

Core rule:

```text
Hypotheses can be bold; confirmed conclusions must remain conservative.
```

## Phase 5.1: Route Model + Unified Route Board

- [ ] Add a `Route` data model.
- [ ] Support route types:
  - [ ] `confirmed_graph_path`
  - [ ] `candidate_graph_path`
  - [ ] `mechanism_hypothesis`
  - [ ] `foothold_hypothesis`
- [ ] Include route fields:
  - [ ] `route_id`
  - [ ] `route_type`
  - [ ] `start`
  - [ ] `target`
  - [ ] `potential_target`
  - [ ] `summary`
  - [ ] `evidence`
  - [ ] `mechanism_explanation`
  - [ ] `historical_support`
  - [ ] `validation_steps`
  - [ ] `missing_evidence`
  - [ ] `next_actions`
  - [ ] `score`
  - [ ] `status`
  - [ ] `confidence`
- [ ] Add `RouteBoardBuilder`.
- [ ] Aggregate:
  - [ ] `candidate-path`
  - [ ] `privilege-path`
  - [ ] `foothold-candidates`
  - [ ] signal findings
  - [ ] pattern cards
  - [ ] controlled principals
- [ ] Add `routes` CLI:
  - [ ] `python -m adpath routes -g data/vintage --top-n 20`
  - [ ] `--source`
  - [ ] `--target`
  - [ ] `--controlled`
  - [ ] `--include-hypothesis`
  - [ ] `--route-type`
  - [ ] `--json`
  - [ ] `--markdown`
  - [ ] `--show-evidence`

## Phase 5.2: Interesting Signal Engine

- [x] Add `SignalFinding`.
- [x] Add signal status values:
  - [x] `observed`
  - [x] `inferred`
  - [x] `pattern_matched`
  - [x] `hypothesis`
  - [x] `confirmed`
- [x] Add `ComputerAccountSignalDetector`.
- [x] Detect Vintage-style Pre-Windows 2000 compatible computer password hypothesis.
- [ ] Add `UserSignalDetector`.
- [ ] Add `GroupSignalDetector`.
- [ ] Add `ServiceAccountSignalDetector`.
- [ ] Add `OUSignalDetector`.
- [ ] Add `GPOSignalDetector`.
- [ ] Add `ADCSTemplateSignalDetector`.
- [ ] Add `GMSASignalDetector`.
- [ ] Add `DMSASignalDetector`.
- [ ] Add `ACLContextSignalDetector`.
- [ ] Add `NamingPatternDetector`.

## Phase 5.3: Knowledge Base Pattern Cards

- [x] Formalize a pattern-card schema.
- [ ] Add fields:
  - [x] `id`
  - [x] `machine`
  - [x] `category`
  - [x] `primitive`
  - [x] `source_object_type`
  - [x] `trigger_keywords`
  - [x] `object_indicators`
  - [x] `graph_indicators`
  - [x] `property_indicators`
  - [x] `relationship_indicators`
  - [x] `hypothesis`
  - [x] `validation`
  - [x] `required_evidence`
  - [x] `missing_information`
  - [x] `next_steps`
  - [x] `confidence`
  - [x] `risk_if_valid`
  - [x] `collection_cost`
  - [x] `historical_examples`
- [x] Add `vintage-pre2k-computer-password`.
- [x] Add `tombwatcher-writespn-targeted-kerberoast`.
- [x] Add `eighteen-ou-createchild-badsuccessor`.
- [x] Add `genericwrite-service-account`.
- [ ] Add `genericwrite-user-identity-control`.
- [ ] Add `genericwrite-group-membership-control`.
- [ ] Add `rbcd-controlled-principal`.
- [ ] Add `adcs-esc1-template`.
- [ ] Add `adcs-esc4-template-control`.
- [ ] Add `gmsa-read-password-impact`.
- [ ] Add `dmsa-badsuccessor`.
- [ ] Add `gpo-control-linked-scope`.
- [ ] Add `admin-to-credential-exposure`.
- [ ] Add `prewindows-compatible-access`.
- [ ] Add `spn-service-account-kerberoast`.

## Phase 5.4: Knowledge Curation From Writeups

- [x] Read each selected machine writeup before writing machine-specific knowledge.
- [x] Extract ordered attack chain steps.
- [x] Mark which steps are visible in BloodHound and which are external.
- [ ] Extract:
  - [ ] entities
  - [ ] credentials
  - [ ] relationships
  - [ ] primitives
  - [ ] mechanism hypotheses
  - [ ] validation commands
  - [ ] missing evidence
  - [ ] post-validation expansion steps
- [x] Store machine-specific reviewed chain records.
- [x] Store generalized reusable pattern cards.
- [x] Keep source evidence references back to writeup files.
- [x] Do not let writeup knowledge become confirmed graph evidence.

## Phase 5.5: Evidence Loop

- [x] Add `evidence add`.
- [x] Support `credential_valid`.
- [x] Record controlled principals.
- [ ] Support `credential_invalid`.
- [ ] Support `ldap_readable`.
- [ ] Support `bloodhound_recollected`.
- [ ] Support `shell_obtained`.
- [ ] Support `hash_obtained`.
- [ ] Support `ticket_obtained`.
- [ ] Support `cert_obtained`.
- [ ] Support `spn_added`.
- [ ] Support `hash_cracked`.
- [ ] Use evidence to promote foothold hypotheses to confirmed footholds.
- [ ] Use negative evidence to down-rank hypotheses.

## Phase 5.6: Controlled Principal Expansion

- [x] Add `candidate-path --controlled`.
- [ ] Add `routes --controlled`.
- [ ] Automatically expand:
  - [ ] ACL paths
  - [ ] group memberships
  - [ ] delegation
  - [ ] RBCD
  - [ ] Kerberos
  - [ ] ADCS
  - [ ] gMSA/dMSA
  - [ ] GPO/OU impact

## Phase 5.7: Route Scoring

- [ ] Score by current evidence strength.
- [ ] Score by historical similarity.
- [ ] Score by privilege escalation potential.
- [ ] Score by validation cost.
- [ ] Penalize uncertainty.
- [ ] Reward routes that create a new controlled identity.
- [ ] Reward permission boundary crossing.
- [ ] Prioritize missing evidence that blocks high-value routes.

## Phase 5.8: Output Experience

- [ ] Text route board.
- [ ] Markdown route board.
- [ ] JSON route board.
- [ ] Group output by:
  - [ ] confirmed graph paths
  - [ ] candidate graph paths
  - [ ] mechanism hypotheses
  - [ ] foothold hypotheses
  - [ ] next best investigations

## Phase 5.9: Real Machine Validation

- [ ] Vintage:
  - [x] FS01 foothold hypothesis
  - [ ] FS01 credential validation evidence
  - [ ] FS01 controlled-principal expansion
- [ ] TombWatcher:
  - [x] WriteSPN chain extraction
  - [x] SPN manipulation pattern card
  - [x] Targeted Kerberoast hypothesis
- [ ] Eighteen:
  - [x] OU CreateChild / BadSuccessor chain extraction
  - [x] dMSA successor/predecessor missing evidence
- [ ] Escape:
  - [ ] ADCS chain extraction
  - [ ] ESC pattern card
- [ ] Certified / Support / Forest:
  - [ ] regression validation
  - [ ] false positive review

## Phase 6: LLM Explanation Layer

- [ ] Keep LLM away from fact confirmation.
- [ ] Feed LLM only structured graph evidence, pattern cards, route records, and missing evidence.
- [ ] Use LLM to:
  - [ ] explain why a route is interesting
  - [ ] translate weak signals into AD mechanisms
  - [ ] connect historical HTB/writeup examples
  - [ ] generate conservative validation guidance
  - [ ] summarize missing evidence
  - [ ] explain ranking

## Completion Criteria

- [ ] The tool can recommend initial foothold candidates without a source principal.
- [ ] The tool can explain why an object such as `FS01$` is interesting.
- [ ] The tool can link current graph objects to historical HTB mechanisms.
- [ ] The tool can generate validation commands without claiming success.
- [ ] The tool can import validation evidence.
- [ ] Validated identities can become controlled principals.
- [ ] Controlled principals can be used for path expansion.
- [ ] The knowledge base stores both machine chains and reusable mechanism patterns.
- [ ] The output clearly separates fact, interpretation, hypothesis, and confirmed evidence.
