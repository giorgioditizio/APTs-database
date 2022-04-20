# CSV files

The following CSV files are the raw data utilized for the generation of the Neo4j DB. Data were either manually collected or automatically collected employing available tools.
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
- **label** contains the type of APT. For example, possible values are activist, criminal, crime-syndicate, nation-state, etc.
- **name** contains the name of the threat group as in MITRE Att&ck.
- **description** contains a short description of the group.
- **goals** contains the goals of the APT. For example, financial gain, espionage, and sabotage.
- **country** contains the allegedly country of origin/location according to the resources consulted.

## Aliases
This CSV file contains the aliases associated to a certain APT. Data were extracted from [***MISP Threat Actor galaxy***](https://www.misp-project.org/galaxy.html#_threat_actor).
- **name** contains the name of the APT from the [***ThreatActors***](#ThreatActors).
- **alias** contains the alias associated to the APT.

## Identities
This CSV file contains the sectors targeted by the APTs. Data were manually extracted from [***Thai Cert Threat Encyclopedia***](https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf).
- **name** contains the name of the sector. For example, energy, defense, telecommunications, etc.

## Malware
This CSV file contains malware employed by the APTs. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck)
- **name** contains the name of the malware. For example, PoisonIvy.
- **platform** contains the list of O.S. platform in which the malware can run. For example, 'Windows,macOS'.

## Techniques
This CSV file contains the techniques (based on MITRE Att\&ck) employed by the APTs. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck).
- **name** contains the name of the technique as reported in MITRE Att\&ck. For example, Pass the Hash.
- **tactic** contains the name of the tactics in which the technique is classified. For example, Lateral movements.
- **platform** contains the O.S. platform where the technique can be implemented.

## Tools
This CSV file contains the tools employed by the APTs. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck).
- **name** contains the name of the tool. For example, RawDisk.

## Vulnerabilities
This CSV file contains the software vulnerability exploited by the APTs. Data were automatically collected from NVD. See [***rel_threatactor_vulnerabilities***](#rel_threatactor_vulnerabilities) for further information.
- **CVE** contains the CVE identifier for the software vulnerability.
- **reservedDate** contains the date when the CVE entry was reserved by MITRE.
- **publishedDate** contains the date when the CVE was published by NVD.
- **baseScore** contains the CVSS base score of the CVE.

## rel_threatactor_vulnerabilities
This CSV file contains the mapping between an APT and the campaign associated to it, along with the software vulnerability and attack vector employed for the initial access. Data were manually collected from the reports consulted.
For some entries multiple sources are available after the **primary source**.
- **name** contains the name of the APT as in [***ThreatActors***](#ThreatActors).
- **vulnerability** contains the CVE ID as in [***Vulnerabilities***](#Vulnerabilities) or the technique employed for the initial access as in [***Techniques***](#Techniques).
- **date_start** contains the alleged date of start/first observation of the campaign as reported in the report consulted.
- **unknown** contains info if the report classify the software vulnerability employed as 0-day at the time. For example, *yes* means 0-day at the time. *no* otherwise.
- **primary source** contains the url to the report/resources consulted from which the data were extracted.

## rel_product_CVE
This CSV file contains the mapping between a CVE and the product,version, and O.S. affected. Data were automatically collected from NVD.
- **product** contains the name of the software product affected by the CVE
- **version** contains the version of the software product affected by the CVE
- **update** contains the update of the software product affected by the CVE, if any. For example, *sp1* for *Word 2010*. *\** if none.
- **product_os** contains the O.S. where the software product can run.
- **CVE** contains the CVE identifier of the software vulnerability.

## rel_threatactor_identities
This CSV file contains the mapping between an APT and the sector targeted. Data were manually extracted from [***Thai Cert Threat Encyclopedia***](https://www.thaicert.or.th/downloads/files/A_Threat_Actor_Encyclopedia.pdf).
- **name** contains the name of the APT as in [***ThreatActors***](#ThreatActors).
- **target** contains the name of the sector as in [***Identities***](#Identities).

## rel_threatactor_malware
This CSV file contains the mapping between an APT and the malware employed. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck).
- **name** contains the name of the APT as in [***ThreatActors***](#ThreatActors).
- **malware** contains the name of the sector as in [***Malware***](#Malware).

## rel_threatactor_techniques
This CSV file contains the mapping between an APT and the technique employed. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck).
- **name** contains the name of the APT as in [***ThreatActors***](#ThreatActors).
- **technique** contains the name of the technique as in [***Techniques***](#Techniques).

## rel_threatactor_tools
This CSV file contains the mapping between an APT and the tool employed. Data were automatically collected using the [***pyattck***](https://github.com/swimlane/pyattck).
- **name** contains the name of the APT as in [***ThreatActors***](#ThreatActors).
- **tool** contains the name of the technique as in [***Tools***](#Tools).