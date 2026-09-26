# Phase 2 Hardening Validation

Validation date: 2026-09-23

## Real BloodHound Imports

| Machine | Source | Nodes | Edges | Warnings |
| --- | --- | ---: | ---: | --- |
| Certified | local Certified BloodHound export | 68 | 473 | `containers` unsupported |
| Support | local Support BloodHound export | 79 | 546 | `containers` unsupported |
| Forest | local Forest BloodHound export | 127 | 1174 | `containers` unsupported |

`containers.json` is currently outside the Phase 2 semantic scope. The parser records it as a warning and continues importing users, groups, computers, domains, OUs, GPOs, and their supported relationships.

## Semantic Checks

Certified:

```text
python -m adpath privilege-path judith.mader -g data/normalized/certified --max-depth 3 --top-n 5
```

Observed path:

```text
JUDITH.MADER@CERTIFIED.HTB --WriteOwner--> MANAGEMENT@CERTIFIED.HTB --GenericWrite--> MANAGEMENT_SVC@CERTIFIED.HTB --MemberOf--> REMOTE MANAGEMENT USERS@CERTIFIED.HTB
```

The path is correctly marked `Incomplete Path` because WriteOwner/GenericWrite require effective ACL and writable-attribute confirmation.

Support:

```text
python -m adpath privilege-path support -g data/normalized/support --max-depth 4 --top-n 5
```

Observed path:

```text
SUPPORT@SUPPORT.HTB --MemberOf--> SHARED SUPPORT ACCOUNTS@SUPPORT.HTB --GenericAll--> DC.SUPPORT.HTB --MemberOf--> DOMAIN CONTROLLERS@SUPPORT.HTB
```

The path is treated as incomplete, not confirmed exploitation, because host/session/credential follow-up is still required.

Forest:

```text
python -m adpath privilege-path svc-alfresco -g data/normalized/forest --max-depth 4 --top-n 5
```

Observed path:

```text
SVC-ALFRESCO@HTB.LOCAL --MemberOf--> SERVICE ACCOUNTS@HTB.LOCAL --MemberOf--> PRIVILEGED IT ACCOUNTS@HTB.LOCAL --MemberOf--> ACCOUNT OPERATORS@HTB.LOCAL
```

The path now separates `PrivilegedGroup` from `DomainPrivilege`; Account Operators is no longer treated as equivalent to Domain Admins.

## False Positive / False Negative Notes

- Ordinary `MemberOf` edges no longer automatically produce privilege gain.
- `highvalue` no longer directly means `DomainPrivilege`; the analyzer distinguishes privileged groups from Tier0 domain privilege.
- `GenericWrite` now emits object-specific candidates for User, Group, Computer, and service-account-like users.
- `WriteDACL` and `WriteOwner` are treated as enabling relationships with missing effective-ACL information, not as complete control.
- `AdminTo` remains local host privilege and reports missing session, stored credential, and service information before inferring domain impact.

Known limitations:

- Containers are not imported yet, so container-only containment edges are not represented.
- Primitive preconditions are currently lightweight type/property checks; deeper tool-specific semantics are reserved for later phases.
- Kerberos, delegation, gMSA/dMSA, and ADCS semantics remain Phase 3 work.
