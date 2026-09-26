# Reference Repositories

These repositories are cloned under `references/repos/` for source reading, design reference, and module study only.

Do not directly modify these repositories. Do not copy their source into `src/`.

| Project | GitHub | Primary Modules To Review | Possible Design Ideas |
| --- | --- | --- | --- |
| Sophos pentesting-skills | https://github.com/sophos/pentesting-skills | AD Recon Skill design, skill workflows, AD enumeration guidance | Skill-style workflow structure, recon checklists, analyst-facing task decomposition |
| Z-Hound | https://github.com/zrnge/Z-Hound | Lightweight graph, HTML visualization, BloodHound data parsing, attack graph display | Minimal static visualization, simple graph export format, browser-first review workflow |
| ImproHound | https://github.com/improsec/ImproHound | Privilege tiering, attack path logic, high/low privilege relationship analysis | Tier-aware scoring, privilege boundary modeling, path prioritization |
| AgentHound | https://github.com/adithyan-ak/agenthound | Node/edge model, graph model, attack path abstraction | Data abstractions for graph reasoning, path objects, relationship-to-primitive mapping |
| BloodHound.py | https://github.com/dirkjanm/BloodHound.py | LDAP/RPC collection, AD object enumeration, relationship extraction, BloodHound JSON structure | Input compatibility, parser expectations, object and relationship vocabulary |
