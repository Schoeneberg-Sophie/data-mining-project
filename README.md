# data-mining-project
Data Mining Project for the Course IE500 Data Mining (UMA)

Data Sources: <br>
[National Vulnerability Database](https://nvd.nist.gov/vuln/data-feeds) <br>
*Note: Data (JSON) is too large to be uploaded on Github. Instead, NVD data for each year is compressed in a .zip file. <br>
For replication of uncompressed data, see dta/NVD_transform.R. Merge files after download.

## Data:
| year | n | kev_ever | kev_90d | kev_180d | kev_365d | median_days |
| --- | --- | --- | --- | --- | --- | --- |
| 2018 | 12,717 | 72 | 0 | 0 | 0 | 1,403.0 |
| 2019 | 16,663 | 126 | 0 | 0 | 0 | 952.0 |
| 2020 | 17,699 | 145 | 0 | 0 | 13 | 573.0 |
| 2021 | 21,543 | 215 | 46 | 91 | 162 | 208.0 |
| 2022 | 26,085 | 130 | 85 | 99 | 112 | 24.0 |
| 2023 | 30,173 | 166 | 121 | 134 | 145 | 6.0 |
| 2024 | 40,645 | 160 | 113 | 132 | 149 | 11.0 |
| 2025 | 49,722 | 197 | 159 | 175 | 192 | 8.0 |
| 2026 | 8,337 | 9 | 6 | 8 | 9 | 15.0 |
<br>

  * `year` & `n`: Shows the total volume of vulnerabilities published each year, demonstrating a steady growth in overall reported software flaws over time (peaking at nearly 50,000 in 2025, with 2026 reflecting a partial year).

  * `kev_ever`: The total count of vulnerabilities from that year's cohort that eventually ended up on CISA's Known Exploited Vulnerabilities (KEV) catalog.

  * `kev_90d` / `kev_180d` / `kev_365d`: These columns track how quickly a vulnerability was added to the KEV catalog relative to its publication date (within 90, 180, or 365 days).

  * `median_days`: The median time (in days) it takes for a vulnerability from that year to be officially recognised as actively exploited in the wild. Notice how this metric has shrunk drastically from over 1,400 days for older vulnerabilities down to single-digit or low double-digit days for recent years, indicating that threat actors exploit newly disclosed flaws much faster today.

<br> <br>
<img width="1902" height="973" alt="image" src="https://github.com/user-attachments/assets/9fdf30fb-b0a1-454e-b2f1-6fd8deb64f25" />
<br>
* **Prevalence:** 1,220 out of ~ 223,00 is roughly 0.55%

## Time Series of Added CVEs

**What this section covers:** how quickly CVEs are added to CISA's Known Exploited Vulnerabilities (KEV) list after they are published, split by publication year. We use it to decide (1) the label window N and (2) which years to train on.

**Key terms**
- **CVE:** one publicly disclosed software flaw (one row in our data).
- **KEV:** CISA's list of flaws confirmed as exploited in real attacks. Being on it is our label (TRUE/FALSE).
- **`days_to_kev`:** days between a CVE's publication date and the date it was added to KEV (`NA` if it was never added).
- **N-day window:** a CVE only counts as positive if it was added to KEV within N days of publication.

### Positive Rates with an N-Day Window

The code counts, per publication year, how many CVEs are on KEV at all (`kev_ever`) and how many were added within 90, 180 and 365 days. It also reports the median `days_to_kev`.

```r
# Snapshot date of the data (latest modification date)
snapshot <- as.Date(substr(max(nvd_all$lastModified), 1, 10))

check <- nvd_all %>%
  mutate(
    year        = as.integer(substr(published, 1, 4)),
    published_d = as.Date(substr(published, 1, 10)),
    days_to_kev = as.numeric(as.Date(kev_date_added) - published_d)
  ) %>%
  group_by(year) %>%
  summarise(
    n            = n(),
    kev_ever     = sum(is_kev),
    kev_90d      = sum(days_to_kev <= 90,  na.rm = TRUE),
    kev_180d     = sum(days_to_kev <= 180, na.rm = TRUE),
    kev_365d     = sum(days_to_kev <= 365, na.rm = TRUE),
    median_days  = median(days_to_kev, na.rm = TRUE)
  )
print(check)
```

**Output**

| year | n | kev_ever | kev_90d | kev_180d | kev_365d | median_days |
| --- | --- | --- | --- | --- | --- | --- |
| 2018 | 12,717 | 72 | 0 | 0 | 0 | 1,403 |
| 2019 | 16,663 | 126 | 0 | 0 | 0 | 952 |
| 2020 | 17,699 | 145 | 0 | 0 | 13 | 573 |
| 2021 | 21,543 | 215 | 46 | 91 | 162 | 208 |
| 2022 | 26,085 | 130 | 85 | 99 | 112 | 24 |
| 2023 | 30,173 | 166 | 121 | 134 | 145 | 6 |
| 2024 | 40,645 | 160 | 113 | 132 | 149 | 11 |
| 2025 | 49,722 | 197 | 159 | 175 | 192 | 8 |
| 2026 | 8,337 | 9 | 6 | 8 | 9 | 15 |

**How to read the table**
- **2018 to 2020 are backfill, not early exploitation.** The KEV list only started in late 2021, and CISA added many older CVEs retrospectively. The median is years, and there are no positives within 180 days. For these years, TRUE means "listed years later", not "exploited soon after publication".
- **2021 is a transition year.** Positives rise from 46 (90 days) to 162 (365 days), so it mixes both situations.
- **From 2022 onwards the pattern is stable.** Most CVEs are added within days or weeks (median 6 to 24 days), and roughly 70 to 80% of all positives fall within 90 days.
- **2026 is a partial year** (only 9 positives so far) and is excluded.
- **Concern:** pooling 2018 to 2021 with later years may teach the model a mixture of two different situations. We test this instead of assuming it (experiment A vs B below).

### Experiments

All experiments are tested on 2025. "Ever" means on KEV at any point up to the snapshot. "90 days" means added within 90 days of publication (only CVEs whose 90-day window is fully observed are used).

| Experiment | Label | Training years | Train CVEs | Train positives | Positive rate (train) | Test positives |
| --- | --- | --- | --- | --- | --- | --- |
| A | ever | 2022-24 | 96,903 | 456 | 0.47% | 197 |
| B | ever | 2018-24 | 165,525 | 1,014 | 0.61% | 197 |
| C | 90 days | 2022-24 | 96,903 | 319 | 0.33% | 159 |

- **A vs B is a clean comparison:** same label and same test set, so any difference in PR-AUC and similar metrics comes from adding 2018 to 2021 to the training data.
- **C cannot be compared with A or B directly:** it has a different label and therefore a different test set (159 vs 197 positives, since the CVEs added after day 90 count as negatives in C). Compare each experiment against its own baselines instead.

**Open question:** does adding 2018 to 2021 help or hurt on the 2025 test set? Experiment A vs B answers this.
