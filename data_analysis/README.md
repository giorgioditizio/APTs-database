# Data analysis

## Scripts and Data

The folder *scripts* contains the scripts utilized for the analysis of the APT campaigns and the effectiveness of the update strategies.

The following CSV files are utilized for the data analysis and simulation:
- [***campaigns_vulnerability_vector_product_version_os***](#campaigns_vulnerability_vector_product_version_os)
- [***air_versions_v2***](#air_versions)
- [***jre_versions_v2***](#jre_versions)
- [***reader_versions_v2***](#reader_versions)
- [***flash_versions_v2***](#flash_versions)
- [***office2016_versions_v2***](#office2016_versions)
- [***air_advisory.xlsx***](#PRODUCT_advisory)
- [***jre_advisory.xlsx***](#PRODUCT_advisory)
- [***reader_advisory.xlsx***](#PRODUCT_advisory)
- [***flash_advisory.xlsx***](#PRODUCT_advisory)
- [***jdk_advisory.xlsx***](#PRODUCT_advisory)
- [***office2016_advisory.xlsx***](#PRODUCT_advisory)
- [***Vulnerabilities_v2***](#Vulnerabilities)

## campaigns_vulnerability_vector_product_version_os
This CSV contains information about the campaigns associated of the APTs. 
It is obtained using the following CYPHER query on the Neo4j DB:
```
CALL apoc.export.csv.query('MATCH (n:APT)<-[:attributed_to]-(c:Campaign)-[:employs]->(t:Technique) OPTIONAL MATCH (c:Campaign)-[:targets]->(v:Vulnerability)<-[:vulnerable_to]-(ver:Version)<-[:has]-(p:Product) RETURN DISTINCT n.name AS APT, id(c) AS campaign, v.name AS vulnerability,t.name AS attack_vector,c.date_start AS exploited_time, v.publishedDate AS published_time, v.reservedDate AS reserved_time, p.name AS product, ver.name AS version, ver.update AS update, ver.os AS os','campaigns_vulnerability_vector_product_version_os.csv', {})
```
The CSV file contains the following entries:
- ***APT*** contains the name of the APT (based on MITRE Att\&ck)
- ***campaign*** contains the unique ID of the campaign.
- ***vulnerability*** contains the CVE ID employed, if any. Empty otherwise.
- ***attack_vector*** contains the technique utilized for the initial access.
- ***exploited_time*** contains the date when the campaign started in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***published_time*** contains the date when the CVE is published by NVD in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***reserved_time*** contains the date when the CVE is reserved by MITRE in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***product*** contains the name of the product affected by the CVE in ***vulnerability***.
- ***version*** contains the version number of the product affected by the CVE in the ***vulnerability*** field.
- ***update*** contains the update number of the product affected by the CVE in the ***vulnerability*** field, * if none.
- ***os*** contains the O.S. with which the version affected can run.


## air_versions
This CSV contains the release date of the version for the software product *Adobe Air*.
- ***product*** contains the name of the product, in this case *Air*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM).

## jre_versions
This CSV contains the release date of the version for the software product *Java JRE*.
- ***product*** contains the name of the product, in this case *JRE*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM).

## reader_versions
This CSV contains the release date of the version for the software product *Acrobat Reader*.
- ***product*** contains the name of the product, in this case *acrobat_reader*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM).

## flash_versions
This CSV contains the release date of the version for the software product *Adobe Flash Player*.
- ***product*** contains the name of the product, in this case *flash_player*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM).

## office2016_versions
This CSV contains the KB release date for the software product *Office*.
- ***product*** contains the name of the product, in this case *office*.
- ***version*** contains the version number, in this case *2016-\**.
- ***update*** contains the KB update.
- ***release_date*** contains the release date of the KB version in the format (YYYY-MM).
- ***details*** contains the CVE that is addressed by the KB version.

## PRODUCT_advisory
This XLSX file contains the mapping between the vendor advisories and the NVD CVE.
- ***product*** contains the name of the product
- ***advisory*** contains the advisory ID
- ***cve*** contains the CVE ID

## Vulnerabilities
This CSV file contains the list of CVEs for the products considered.
