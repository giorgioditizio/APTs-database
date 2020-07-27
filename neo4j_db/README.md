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

#### APT
- ***labels*** describes the type of APT. For example, possible values are activist, criminal, crime-syndicate 33 , nation-state, etc.
- ***name*** contains the name of the threat group as in MITRE Att\&ck.
- ***description*** contains a short description of the group.
- ***goals*** contains the goals of the APT. For example, financial gain, espionage, and sabotage.

#### Country
- ***name*** contains the name of the Country. It represents the Country in which an APT is allegedly to have origin/location according to the resources consulted.

#### Alias
- ***name*** contains another name associated to a certain APT. For example APT18 is also called *Dynamite Panda*, *Scandium*, *Webly*, etc.

#### Identity
- ***name*** contains the name of a sector targeted by a certain APT. For example, energy, defense, telecommunications, etc;