# CSV files

The following CSV files are the raw data utilized for the generation of the Neo4j DB:
- [***ThreatActors***](#ThreatActors)
- [***Aliases***](#Aliases)
- [***Identities***](#Identities)
- [***Malware***](#Malware)
- [***Techniques***](#Techniques)
- [***Tools***](#Tools)
- [***Vulnerabilities***](#Vulnerabilities)
- [***rel_product_CVE***](#rel_product_CVE)
- [***rel_threatactor_identities***](#rel_threatactor_identities)
- [***rel_threatactor_malware***](#rel_threatactor_malware)
- [***rel_threatactor_techniques***](#rel_threatactor_techniques)
- [***rel_threatactor_tools***](#rel_threatactor_tools)
- [***rel_threatactor_vulnerabilities***](#rel_threatactor_vulnerabilities)

## ThreatActors
This CSV file contains informarmation about the APTs considered in the analysis. Data were manually extracted from [***MITRE Att\&ck***](https://attack.mitre.org/).
- **label** contains the type of APT. For example, possible values are activist, criminal, crime-syndicate 33 , nation-state, etc.
- **name** contains the name of the threat group as in MITRE Att&ck.
- **description** contains a short description of the group.
- **goals** contains the goals of the APT. For example, financial gain, espionage, and sabotage.
- **country** contains the allegedly country of origin/location according to the resources consulted.

## Aliases
This CSV file contains the aliases associated to a certain APT. Data were extracted from [***MISP Threat Actor galaxy***](https://www.misp-project.org/galaxy.html#_threat_actor).
- **name** contains the name of the APT from the [***ThreatActors***](#ThreatActors).
- **alias** contains the alias associated to the APT.
