# STATUS

## Badges Applied For

We apply for the following artifact badges:

- Artifacts Available
- Artifacts Functional
- Artifacts Reusable

## Justification for Artifacts Available

ThreatCraft is publicly available as a source-code artifact through the project repository. The repository includes the source code, example input files, threat libraries, example outputs, documentation, and license information required to inspect and evaluate the artifact.

## Justification for Artifacts Functional

ThreatCraft can be executed locally as a Python-based GUI application. The artifact provides the core functionality described in the paper, including DFD loading, rule-based attack path generation, attack graph rendering, and LLM-based attack scenario generation and refinement.

The repository also provides example files that can be used to test the tool and check whether the artifact runs correctly in the local environment.

## Justification for Artifacts Reusable

ThreatCraft is organized as a reusable software artifact. Its domain-specific threat libraries are structured under `code/backend/threat_library/`, where assets, threats, and related mappings for each domain are managed in a modular form.

Users can update or extend the artifact by adding new assets, threats, or mappings to these library files. Because the threat libraries are written in widely used JSON formats, they can be easily inspected, modified, and reused without changing the core implementation. 

In addition, new domains can be supported by adding or modifying the corresponding domain-specific library files. This structure allows ThreatCraft to be reused not only for the evaluation cases described in the paper, but also for additional systems, domains, and threat analysis scenarios.
