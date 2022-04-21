# Neo4j Database

This folder contains the dump of the Neo4j database containing data about APTs, malware, campaigns, vulnerabilities, products, and versions affected. The folder contains also the raw data if you want to create the DB from scratch.

Please refer to the Neo4j documentation for more information.

## External source of data
- Data related to malware, techniques, and tools is obtained using [pyattck](https://github.com/swimlane/pyattck).
- Data related to Aliases is obtained from [MISP Threat Actor galaxy](https://github.com/MISP/misp-galaxy/blob/main/clusters/threat-actor.json).
- Data related to affected versions by CVE is obtained from [NVD](https://nvd.nist.gov/)


## Setting up

- Load the dump in a database called *graph.db* (default). **IMPO:** the database must be shutdown first.
```
./bin/neo4j-admin load --from=LOCATION_OF_DUMP_FILE/APTs_DB.dump --database=graph.db --force
```
See [dump load in Neo4j](https://neo4j.com/docs/operations-manual/current/tools/dump-load/) for more details.

## Database structure

The following nodes and relationship are present in the database.

### Nodes
Each node contains one or more field.

#### APT
This node represents an APT we considered in the analysis.
- ***labels*** contains the type of APT. For example, possible values are activist, criminal, crime-syndicate, nation-state, etc.
- ***name*** contains the name of the threat group as in MITRE Att\&ck.
- ***description*** contains a short description of the group.
- ***goals*** contains the goals of the APT. For example, financial gain, espionage, and sabotage.

#### Country
This node represents a country in which an APT is allegedly to have origin according to the resources consulted.
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
- ***reservedDate*** contains the date when the CVE has been *reserved* by MITRE (in the format YYYY-MM).
- ***publishedDate*** contains the date when the CVE has been *puslished* by NVD (in the format YYYY-MM).

#### Campaign
This node represents a campaign carried by a certain APT
- ***date_start*** contains the date when the campaign was first observed (in the format YYYY-MM).

#### Malware
This node represent a malicious software employed by a certain APT.
- ***name*** contains the name of the malware.
- ***platform*** contains the list of platforms in which the malware can run. For example, *Linux*,*Windows*, *macOS*, etc.

#### Tool
This node represents a legitimate tool available that is known to be used by an APT.
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
- *APT -uses-> Malware* defines a link between a malware and an APT.
- *APT -uses-> Tool* defines a link between a tool and an APT.
- *APT -uses-> Technique* defines a link between a technique and an APT.
- *APT -origin-> Country* defines a link between an APT and the allegedly country of origin.
- *APT <-attributed_to- Campaign* defines a link between an APT and a campaign.
- *Campaign -targets-> Vulnerability* defines a link between a software vulnerability exploited in a specific campaign.
- *APT -targets-> Identity* defines a sector targeted by an APT.
- *APT <-alias- Alias* defines a link between the a different name associated to an APT.
- *Product -has-> Version* defines which version is associated to a product.
- *Version -vulnerable_to-> Vulnerability* defines a link between a CVE and a version of a product affected by the CVE.
- *Campaign -employs-> Technique* defines a link between a technique for *initial access* and a campaign.
