#this script sets the Neo4j DB with the data about the APT attacks
#@author: Giorgio Di Tizio - giorgio.ditizio@unitn.it

from neo4j_controller import Neo4j_Controller
import time
uri = 'bolt://localhost:7687'
user = 'neo4j'
password = ''
controller = Neo4j_Controller(uri,user,password)

vanilla_version = True
if vanilla_version:
	#clean the DB
	print("Cleaning the Neo4j DB...")
	controller.clean()
	time.sleep(5)
	print("Done cleaning")

	print("####################")
	print("Creating nodes...")

	#create all the nodes
	controller.create_APTs()
	controller.create_countries()
	controller.create_vulnerabilities()
	controller.create_malware()
	controller.create_identities()
	controller.create_tools()
	controller.create_aliases()
	controller.create_techniques()
	controller.create_products()
	controller.create_versions()
	controller.create_campaigns()
	print("Done nodes creation")
	print("####################")
	time.sleep(5)

	#create all the relations
	print("Creating relationships...")
	controller.create_rel_APT_country()
	controller.create_rel_APT_malware()
	controller.create_rel_APT_campaign_vulnerability()
	controller.create_rel_campaign_techniques()
	controller.create_rel_APT_identity()
	controller.create_rel_APT_tool()
	controller.create_rel_APT_technique()
	controller.create_rel_APT_alias()
	controller.create_rel_product_version()
	controller.create_rel_version_CVE()

	controller.delete_fake_techniques()

	print("Done relationships creation")
	print("####################")
	time.sleep(5)

	print("Generating CSV file for APT-Campaign-Vulnerability-AttackVector-Product-Version-OS")
	controller.get_campaign_vulnerability_vector_product_version_os()

controller.close()
