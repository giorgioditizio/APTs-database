#this script loads the CSV files to create nodes and relationships.
#This type of cypher query works for small files only. Use PERIODIC commit if necessary
#@author: Giorgio Di Tizio - giorgio.ditizio@unitn.it

from neo4j import GraphDatabase


#queries to create the DB
query_clean = "MATCH (n) DETACH DELETE n"
query_create_APTs = "LOAD CSV WITH HEADERS FROM 'file:///ThreatActors.csv' AS line CREATE (:APT { name: line.name, labels: line.labels, description: line.description, goals: line.goals})"
query_create_countries = "LOAD CSV WITH HEADERS FROM 'file:///ThreatActors.csv' AS line MERGE (:Country {name: line.country})"
query_create_vulnerabilities = "LOAD CSV WITH HEADERS FROM 'file:///Vulnerabilities.csv' AS line MERGE (:Vulnerability { name: line.CVE, reservedDate: date(line.reservedDate), publishedDate : date(line.publishedDate), baseScore : line.baseScore})"
query_create_malware = "LOAD CSV WITH HEADERS FROM 'file:///Malware.csv' AS line CREATE (:Malware { name: line.name, platform: line.platform})"
query_create_identities = "LOAD CSV WITH HEADERS FROM 'file:///Identities.csv' AS line CREATE (:Identity { name: line.name, identity_class: line.identity_class})"
query_create_tools = "LOAD CSV WITH HEADERS FROM 'file:///Tools.csv' AS line CREATE (:Tool { name: line.name, description: line.description})"
query_create_aliases = "LOAD CSV WITH HEADERS FROM 'file:///Aliases.csv' AS line CREATE (:Alias { name: line.alias})"
query_create_techniques = "LOAD CSV WITH HEADERS FROM 'file:///Techniques.csv' AS line CREATE (:Technique { name: line.name, tactic: line.tactic, platforms: line.platforms, permissions: line.permissions, bypass: line.bypass, effective_permissions: line.effective_permissions, network: line.network, remote: line.remote})"
query_create_products = "LOAD CSV WITH HEADERS FROM 'file:///rel_product_CVE.csv' AS line MERGE (:Product { name: line.product})"
query_create_versions = "LOAD CSV WITH HEADERS FROM 'file:///rel_product_CVE.csv' AS line MERGE (:Version { name: line.version, product: line.product, update: line.update, os:line.product_os})"
query_create_campaigns = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_vulnerabilities.csv' AS csvLine MERGE (c:Campaign { actor: csvLine.name, date_start: date(csvLine.date_start)})"
query_create_rel_APT_country = "LOAD CSV WITH HEADERS FROM 'file:///ThreatActors.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(country:Country {name: csvLine.country}) CREATE (actor)-[:origin]->(country)"
query_create_rel_APT_malware = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_malware.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(malware:Malware {name: csvLine.malware}) CREATE (actor)-[:uses]->(malware)"
query_create_rel_APT_campaign_vulnerability = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_vulnerabilities.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(vulnerability:Vulnerability {name: csvLine.vulnerability}) MERGE (camp:Campaign { actor: csvLine.name, date_start: date(csvLine.date_start)}) MERGE (actor)<-[:attributed_to]-(camp) MERGE (camp)-[:targets]->(vulnerability)"
query_create_rel_campaign_techniques = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_vulnerabilities.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(technique:Technique {name:csvLine.vulnerability}) MERGE (camp:Campaign { actor: csvLine.name, date_start: date(csvLine.date_start)}) MERGE (actor)<-[:attributed_to]-(camp) MERGE (camp)-[:targets]->(vulnerability) MERGE (camp)-[:employs]->(technique)"
query_create_rel_APT_identity = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_identities.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(identity:Identity {name: csvLine.target})CREATE (actor)-[:targets]->(identity)"
query_create_rel_APT_tool = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_tools.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(tool:Tool {name: csvLine.tool}) CREATE (actor)-[:uses]->(tool)"
query_create_rel_APT_technique = "LOAD CSV WITH HEADERS FROM 'file:///rel_threatactor_techniques.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(technique:Technique {name: csvLine.technique}) MERGE (actor)-[:uses]->(technique)"
query_create_rel_APT_alias = "LOAD CSV WITH HEADERS FROM 'file:///Aliases.csv' AS csvLine MATCH (actor:APT {name: csvLine.name}),(alias:Alias {name: csvLine.alias}) CREATE (alias)-[:alias]->(actor)"
query_create_rel_product_version = "LOAD CSV WITH HEADERS FROM 'file:///rel_product_CVE.csv' AS csvLine MATCH (product:Product {name: csvLine.product}),(version:Version {name: csvLine.version, product: csvLine.product, update: csvLine.update, os:csvLine.product_os}) MERGE (product)-[:has]->(version)"
query_create_rel_version_CVE = "LOAD CSV WITH HEADERS FROM 'file:///rel_product_CVE.csv' AS csvLine MATCH (vulnerability:Vulnerability {name: csvLine.CVE}),(version:Version {name: csvLine.version, product: csvLine.product, update: csvLine.update, os: csvLine.product_os}) MERGE (version)-[:vulnerable_to]->(vulnerability)"
query_delete_fake_technique = "MATCH (:Campaign)-[t:targets]-(a) WHERE NOT EXISTS(a.name) DELETE t,a"

#queries to extract data to CSV files
#extract APT,CAMP,VULNERABILITY(if any),ATTACK_VECTOR,EXPLOIT_DATE,PUBLISHED_DATE(if any),RESERVED_DATE(if any),PRODUCT(if any),VERSION(if any),UPDATE(if any),O.S.(if any)
query_campaign_vulnerability_vector_product_version_os = "CALL apoc.export.csv.query('MATCH (n:APT)<-[:attributed_to]-(c:Campaign)-[:employs]->(t:Technique) OPTIONAL MATCH (c:Campaign)-[:targets]->(v:Vulnerability)<-[:vulnerable_to]-(ver:Version)<-[:has]-(p:Product) RETURN DISTINCT n.name AS APT, id(c) AS campaign, v.name AS vulnerability,t.name AS attack_vector,c.date_start AS exploited_time, v.publishedDate AS published_time, v.reservedDate AS reserved_time, p.name AS product, ver.name AS version, ver.update AS update, ver.os AS os','campaigns_vulnerability_vector_product_version_os.csv', {})"

class Neo4j_Controller(object):
    def __init__(self, uri, user, password):
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self):
        self._driver.close()

    #clean the entire DB: eliminate nodes and relationships
    def clean(self):
        with self._driver.session() as session:
            session.run(query_clean)

    def delete_fake_techniques(self):
        with self._driver.session() as session:
            session.run(query_delete_fake_technique)

    #create nodes for the APTs
    def create_APTs(self):
        with self._driver.session() as session:
            session.run(query_create_APTs)

    #create nodes for countries
    def create_countries(self):
        with self._driver.session() as session:
            session.run(query_create_countries)

    #create nodes for vulnerabilities
    def create_vulnerabilities(self):
        with self._driver.session() as session:
            session.run(query_create_vulnerabilities)

    #create nodes for malware
    def create_malware(self):
        with self._driver.session() as session:
            session.run(query_create_malware)    

    #create nodes for identities
    def create_identities(self):
        with self._driver.session() as session:
            session.run(query_create_identities)  

    #create nodes for tools
    def create_tools(self):
        with self._driver.session() as session:
            session.run(query_create_tools) 

    #create nodes for aliases
    def create_aliases(self):
        with self._driver.session() as session:
            session.run(query_create_aliases) 

    #create nodes for techniques
    def create_techniques(self):
        with self._driver.session() as session:
            session.run(query_create_techniques) 

    #create nodes for products
    def create_products(self):
        with self._driver.session() as session:
            session.run(query_create_products) 

    #create nodes for versions
    def create_versions(self):
        with self._driver.session() as session:
            session.run(query_create_versions) 

    def create_campaigns(self):
        with self._driver.session() as session:
            session.run(query_create_campaigns) 

    #create relation APT-Country
    def create_rel_APT_country(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_country) 

    #create relation APT-malware
    def create_rel_APT_malware(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_malware) 

    #create relation APT-campaign-vulnerability
    def create_rel_APT_campaign_vulnerability(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_campaign_vulnerability) 

    #create relation campaign-techniques for initial access
    def create_rel_campaign_techniques(self):
        with self._driver.session() as session:
            session.run(query_create_rel_campaign_techniques)

    #create relation APT-identity targeted
    def create_rel_APT_identity(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_identity) 

    #create relation APT-tool
    def create_rel_APT_tool(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_tool)

    #create relation APT-technique
    def create_rel_APT_technique(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_technique) 

    #create relation APT-alias
    def create_rel_APT_alias(self):
        with self._driver.session() as session:
            session.run(query_create_rel_APT_alias) 

    #create relation product-version
    def create_rel_product_version(self):
        with self._driver.session() as session:
            session.run(query_create_rel_product_version)

    #create relation version-CVE
    def create_rel_version_CVE(self):
        with self._driver.session() as session:
            session.run(query_create_rel_version_CVE) 

    #get mix info about APT,campaign,vulnerability,attack vector, product, versions and O.S.
    def get_campaign_vulnerability_vector_product_version_os(self):
        with self._driver.session() as session:
            session.run(query_campaign_vulnerability_vector_product_version_os)

