# NEO4J Database

This folder contains the dump of the Neo4j database containing data about APTs, campaigns, vulnerabilities, products, etc.

## Setting up

See https://neo4j.com/docs/operations-manual/current/tools/dump-load/ for more details.
- Load the dump in a database called *graph.db* (default). **IMPO:** the database must be shutdown first.: 
```
./bin/neo4j-admin load --from=LOCATION_OF_DUMP_FILE/TI_neo4j.dump --database=graph.db --force
```

## Database structure