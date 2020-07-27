# Neo4j Database

This folder contains the dump of the Neo4j database containing data about APTs, campaigns, vulnerabilities, products, etc.

## Setting up

See https://neo4j.com/docs/operations-manual/current/tools/dump-load/ for more details.
- Load the dump in a database called *graph.db* (default). **IMPO:** the database must be shutdown first.: 
```
./bin/neo4j-admin load --from=LOCATION_OF_DUMP_FILE/TI_neo4j.dump --database=graph.db --force
```

## Database structure

The following nodes and relationship are present in the database.

### Nodes
Each node contains one or more field.

#### APT
This node represents an APT we considered in the analysis.
- ***labels*** describes the type of APT. For example, possible values are activist, criminal, crime-syndicate 33 , nation-state, etc.
- ***name*** contains the name of the threat group as in MITRE Att\&ck.
- ***description*** contains a short description of the group.
- ***goals*** contains the goals of the APT. For example, financial gain, espionage, and sabotage.

#### Country
This node represents a country in which an APT is allegedly to have origin/location according to the resources consulted.
- ***name*** contains the name of the Country.

#### Alias
This node represents an alias associated to a certain APT.
- ***name*** contains another name associated to a certain APT. For example APT18 is also called *Dynamite Panda*, *Scandium*, *Webly*, etc.

#### Identity
This node represents a sector that is targeted by a certain APT
- ***name*** contains the name of a sector targeted by a certain APT. For example, energy, defense, telecommunications, etc;

#### Vulnerability
This node represents a software vulnerability exploited by an APT.
- ***name*** contains the CVE associated to the vulnerability.
- ***baseScore*** contains the CVSS Severity and Metrics Base score of the CVE.
- ***reservedDate*** contains the date when the CVE has been *reserved* by MITRE (in the format MM-YYYY).
- ***publishedDate*** contains the date when the CVE has been *puslished* by NVD (in the format MM-YYYY).

#### Campaign
This node represents a campaign carried by a certain APT
- ***date_start*** contains the date when the campaign was first observed.

#### Malware
This node represent a malicious software employed by a certain APT.
- ***name*** contains the name of the malware.
- ***platform*** contains the list of platforms in which the malware can run. For example, *Linux*,*Windows*, *macOS*, etc.

#### Tool
This node represents a legitimate tool available that is exploited by a threat actor during their campaigns.
- ***name*** contains the name of the tool. For example, *Winexe*.

#### Technique
This node represents a technique used by an APT to compromise the targed
- ***name*** contains the name of the technique as define in MITRE Att\&ck. For example, *File and Directory Discovery*.
- ***tactic*** contains the goal of the technique. For example, *initial access*, *command-and-control*, etc.
- ***platforms*** contains the platform affected. For example,  *Linux*,*Windows*, *macOS*, etc.
- ***permissions*** contains the permissions required to implement the technique. For example, *user*, *administrator*, etc.

#### Product
This node represents a software product that is vulnerable to at least a CVE exploited by an APT.
- ***name*** contains the name of the software product. For example, *flash_player*.

#### Version
This node represents a version related to a specific software product for which a CVE is exploited by an APT.
- ***name*** contains the version of the product.
- ***product*** contains the software product name.
- ***update*** contains the update number, if any. For example, *sp1* for Windows XP.
- ***os*** contains the O.S. name in which the software version can run.

### Relationships
The relationships link different nodes types.
- APT --uses-> Malware: defines which malware is used by a certain APT.