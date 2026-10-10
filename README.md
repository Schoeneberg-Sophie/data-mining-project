# data-mining-project
Data Mining Project for the Course IE500 Data Mining (UMA)

Data Sources: <br>
[National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds) <br>
*Note: Data is too large to be uploaded on Github. 


# Dataset Structure Analysis

## CISA KEV Dataset
* **Total Rows:** 1,734

| Variable | Primary Type | Subtype Structure | Non-Missing Count | Missing Count |
| :--- | :--- | :--- | :--- | :--- |
| cveID | character | Atomic Vector (Flat) | 1,734 | 0 |
| vendorProject | character | Atomic Vector (Flat) | 1,734 | 0 |
| product | character | Atomic Vector (Flat) | 1,734 | 0 |
| vulnerabilityName | character | Atomic Vector (Flat) | 1,734 | 0 |
| dateAdded | Date | Atomic Vector (Flat) | 1,734 | 0 |
| shortDescription | character | Atomic Vector (Flat) | 1,734 | 0 |
| requiredAction | character | Atomic Vector (Flat) | 1,734 | 0 |
| dueDate | Date | Atomic Vector (Flat) | 1,734 | 0 |
| knownRansomwareCampaignUse | character | Atomic Vector (Flat) | 1,734 | 0 |
| forensicTriage | character | Atomic Vector (Flat) | 1,734 | 0 |
| notes | character | Atomic Vector (Flat) | 1,734 | 0 |
| cwes | character | Atomic Vector (Flat) | 1,559 | 175 |

---

## NVD Dataset
* **Total Rows:** 68,763

| Variable | Primary Type | Subtype Structure | Non-Missing Count | Missing Count |
| :--- | :--- | :--- | :--- | :--- |
| id | character | Atomic Vector (Flat) | 68,763 | 0 |
| sourceIdentifier | character | Atomic Vector (Flat) | 68,763 | 0 |
| published | character | Atomic Vector (Flat) | 68,763 | 0 |
| lastModified | character | Atomic Vector (Flat) | 68,763 | 0 |
| vulnStatus | character | Atomic Vector (Flat) | 68,763 | 0 |
| cveTags | list | Nested Dataframe | 68,763 | 0 |
| descriptions | list | Nested Dataframe (lang, value) | 68,763 | 0 |
| affected | list | Nested Dataframe (source, affectedData) | 68,763 | 0 |
| metrics | data.frame | Nested List | 343,815 | 0 |
| weaknesses | list | Nested Dataframe (source, type, description) | 68,763 | 0 |
| configurations | list | Nested Dataframe (nodes) | 68,763 | 0 |
| references | list | Nested Dataframe (url, source, tags) | 68,763 | 0 |
| cisaExploitAdd | character | Atomic Vector (Flat) | 169 | 68,594 |
| cisaActionDue | character | Atomic Vector (Flat) | 169 | 68,594 |
| cisaRequiredAction | character | Atomic Vector (Flat) | 169 | 68,594 |
| cisaVulnerabilityName | character | Atomic Vector (Flat) | 169 | 68,594 |
| evaluatorComment | character | Atomic Vector (Flat) | 2 | 68,761 |
