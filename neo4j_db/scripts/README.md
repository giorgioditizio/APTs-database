# Scripts to set up Neo4j DB

These scripts allows one to set up the Neo4j DB from the raw CSV files.

## Procedure

- Create a Neo4j DB
- Load the CSV files in the *import* folder of the Neo4j DB
- Install the *APOC* Plugin in Neo4j
- Start the Neo4j DB
- Install the requirements in requirements.txt: ```pip install -r requirements.txt```
- Run the python script *neo4j_queries.py* (IMPO: modify the user and password fields for your DB). It includes the *neo4j_controller.py* script that must be present in the same folder. 

## neo4j_queries.py

This script connects to the Neo4j database, retrieves and execute the CYPHER queries from the *neo4j_controller.py*

## neo4j_controller.py

This script contains the queries to create nodes and relationships loading data from CSV files.
