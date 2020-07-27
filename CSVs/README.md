# CSV files

The following CSV files are utilized for the data analysis and simulation:
- [***campaigns_vulnerabilities***](#campaigns_vulnerabilities)
- [***campaigns_vulns_products***](#campaigns_vulns_products)
- [***campaigns_vulns_products_versions***](#campaigns_vulns_products_versions)
- [***air_versions***](#air_versions)
- [***jre_versions***](#jre_versions)
- [***reader_versions***](#reader_versions)
- [***flash_versions***](#flash_versions)


## campaigns_vulnerabilities
This CSV contains information about the campaigns associated to a certain APT with the corresponding CVE and/or attack vector employed. It is obtained from the Neo4j database with the following query:
```
MATCH p=(country:Country)<-[:origin]-(n:APT)<-[:attributed_to]-(c:Campaign),q=(c:Campaign)-[:targets]->(cve:Vulnerability) RETURN DISTINCT n.name AS APT,country.name AS country,ID(c) AS campaign,cve.name AS vulnerability,c.date_start AS exploited_time, cve.reservedDate AS reserved_time, cve.publishedDate AS published_time UNION ALL MATCH w=(country:Country)<-[:origin]-(n:APT)<-[:attributed_to]-(c:Campaign)-[:employs]->(t:Technique) RETURN DISTINCT n.name AS APT,country.name AS country,ID(c) AS campaign,t.name AS vulnerability,c.date_start AS exploited_time, null AS reserved_time, null AS published_time
```
- ***APT*** contains the name of the APT (based on MITRE Att\&ck)
- ***country*** contains the allegedly country of origin for the APT.
- ***campaign*** contains the ID of the campaign, unique among all campaigns.
- ***vulnerability*** contains either a CVE ID or the attack vector employed.
- ***exploited_time*** contains the date when the campaign started in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***reserved_time*** contains the date when the CVE is reserved by MITRE in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity) if the ***vulnerability*** field contains a CVE, *NULL* otherwise.
- ***published_time*** contains the date when the CVE is published by NVD in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity) if the ***vulnerability*** field contains a CVE, *NULL* otherwise.

## campaigns_vulns_products
This CSV contains information about the campaigns associated to a certain APT that exploit a software vulnerability. It is obtained from the Neo4j database with the following query:
```
MATCH (n:APT)<-[:attributed_to]-(c:Campaign)-[:targets]->(v:Vulnerability)<-[:vulnerable_to]-(ver:Version)<-[:has]-(p:Product) RETURN DISTINCT n.name AS APT, id(c) AS campaign, v.name AS vulnerability,c.date_start AS exploited_time, v.publishedDate AS published_time, v.reservedDate as reserved_time, p.name AS product
```
- ***APT*** contains the name of the APT (based on MITRE Att\&ck)
- ***campaign*** contains the ID of the campaign, unique among all campaigns.
- ***vulnerability*** contains the CVE ID employed.
- ***exploited_time*** contains the date when the campaign started in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***reserved_time*** contains the date when the CVE is reserved by MITRE in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***published_time*** contains the date when the CVE is published by NVD in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***product*** contains the name of the product affected by the CVE in ***vulnerability***.

## campaigns_vulns_products_versions
This CSV contains information about the campaigns associated to a certain APT that exploit a software vulnerability with additional information about the version affected. This data contains ***ONLY*** products running *Windows O.S.*. It is obtained from the Neo4j database with the following query:
```
MATCH (n:APT)<-[:attributed_to]-(c:Campaign)-[:targets]->(v:Vulnerability)<-[:vulnerable_to]-(ver:Version)<-[:has]-(p:Product) WHERE ver.os CONTAINS \"windows\" OR ver.os CONTAINS \"*\" RETURN DISTINCT n.name AS APT, id(c) AS campaign, v.name AS vulnerability,c.date_start AS exploited_time, v.publishedDate AS published_time, v.reservedDate AS reserved_time, p.name AS product, ver.name AS version, ver.update AS update, ver.os AS os
```
- ***APT*** contains the name of the APT (based on MITRE Att\&ck)
- ***campaign*** contains the ID of the campaign, unique among all campaigns.
- ***vulnerability*** contains the CVE ID employed.
- ***exploited_time*** contains the date when the campaign started in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***reserved_time*** contains the date when the CVE is reserved by MITRE in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***published_time*** contains the date when the CVE is published by NVD in the format (YYYY-MM-DD, DD is always the first day of the month as we have only month granularity).
- ***product*** contains the name of the product affected by the CVE in ***vulnerability***.
- ***version*** contains the version number of the product affected by the CVE in ***vulnerability***.
- ***update*** contains the update number of the product affected by the CVE in ***vulnerability***, * if none.
- ***os*** contains the O.S. with which the version affected can run. In this case only *Windows* O.S. is considered.


## air_versions
This CSV contains the release date of the version for the software product *Adobe Air*.
- ***product*** contains the name of the product, in this case *Air*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM)

## jre_versions
This CSV contains the release date of the version for the software product *Java JRE*.
- ***product*** contains the name of the product, in this case *JRE*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM)

## reader_versions
This CSV contains the release date of the version for the software product *Acrobat Reader*.
- ***product*** contains the name of the product, in this case *acrobat_reader*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM)

## flash_versions
This CSV contains the release date of the version for the software product *Adobe Flash Player*.
- ***product*** contains the name of the product, in this case *flash_player*.
- ***version*** contains the version number.
- ***update*** contains the update, * if not present.
- ***release_date*** contains the release date of the software version in the format (YYYY-MM)
