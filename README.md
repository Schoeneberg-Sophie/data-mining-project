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


## Feature Evaluation: Which Variables Help Predict KEV Listing?

**What this section covers:** a first look at every candidate predictor in the NVD table, to decide which variables go into the models. It answers three questions: how complete is each variable, how strongly does it relate to the label, and could it leak the answer or behave differently in 2025?

**Setup**
- **Label:** CVE added to KEV within 90 days of publication.
- **Data used:** development set only (CVEs published 2022 to 2024, 96,903 CVEs, 319 positives, base rate 0.33%). 2025 was not touched, so feature choices cannot leak the test set.
- **Metric:** single-variable AUC (0.5 = no signal, 1 = perfect separation, below 0.5 = signal in the opposite direction). It looks at one variable at a time, so a weak AUC does not rule out a variable that helps in combination.

### Key Takeaways
1. **No positive CVE is missing CVSS or vendor data.** Models can only meaningfully rank CVEs that NVD has already analysed. We restrict the modelling population to those (see below).
2. **CVSS severity, weakness type (CWE), vendor/product and the reporting organisation (CNA) carry the signal.** The rarely informative variables are text length and most CVSS sub-scores.
3. **Reference counts and other CVSS versions are risky.** References accumulate after publication, and the other CVSS versions exist only for certain years.
4. **The number of affected product entries (`n_cpe_matches`) is surprisingly strong,** but its value depends on the vendor and it is measured at the snapshot date, so we treat it with care.
5. **The test year looks different from the training years** (more CVEs without vendor data in 2025), which affects how results should be read.

### 1. Missing Data Is Not Random

| Group (dev set) | CVEs | Positives | Expected at base rate |
| --- | --- | --- | --- |
| No CVSS v3.1 score | 4,751 | 0 | about 16 |
| No vendor / product | 11,554 | 0 | about 38 |
| No CWE | 4,711 | 0 | about 16 |

The pattern is identical in 2022, 2023 and 2024, so it is structural. These groups largely mean "not yet analysed by NVD". The data cannot tell us the direction: NVD may analyse KEV-listed CVEs quickly, or exploited CVEs may simply be the prominent ones that get analysed first. Either way, a CVE without analysis is never a positive in our data.

**Decision?:** restrict the modelling population to CVEs with a CVSS v3.1 score and vendor data, in training and test years alike, and report how many CVEs this removes per year. A model built this way works at the point when analysis is available, not on the day of publication.

**Shift in 2025:** the share of CVEs with vendor data falls from 94 to 95% (2022 and 2023) to 79% (2024) and 61% (2025), and CVSS v3.1 is missing for 11% of 2025 CVEs. This looks like an analysis backlog (not verified). Removing these CVEs loses no positives, but the 2025 test population becomes smaller with a higher positive rate, so precision@k is not directly comparable with a model evaluated on all CVEs.

### 2. Numeric Variables

| Variable | Missing (dev) | AUC | AUC 2022 / 2023 / 2024 | Decision? |
| --- | --- | --- | --- | --- |
| `cvssV31_score` | 4.9% | 0.719 | 0.73 / 0.67 / 0.76 | **Keep** (also our CVSS baseline) |
| `cvssV31_impact` | 4.9% | 0.708 | 0.71 / 0.67 / 0.75 | Redundant with score (correlation 0.86), use components instead |
| `cvssV31_exploitability` | 4.9% | 0.566 | 0.56 / 0.54 / 0.59 | Drop (weak) |
| `n_cpe_matches` | 0% | 0.810 | 0.78 / 0.84 / 0.80 | **Candidate**, see section 5 |
| `n_products` | 0% | 0.771 | 0.74 / 0.77 / 0.79 | Redundant with `n_cpe_matches` (0.81), keep one |
| `n_vendors` | 0% | 0.605 | 0.54 / 0.61 / 0.64 | Drop (weak) |
| `n_references` | 0% | 0.732 | 0.78 / 0.78 / 0.66 | Exclude from main model (section 4) |
| `n_ref_patch_tag`, `n_ref_exploit_tag` | 0% | 0.567, 0.537 | unstable | Exclude from main model |
| `cvssV30_score`, `cvssV40_score`, `cvssV2_score` | 82 to 96% | 0.76 to 0.90 | mostly missing | Drop (section 4) |
| `desc_nchar` | 0% | 0.487 | 0.53 / 0.54 / 0.42 | Drop (no signal, unstable) |

### 3. Categorical Variables

**CVSS v3.1 components** (positive rate per level, base rate 0.33%)

| Variable | Pattern |
| --- | --- |
| Severity | CRITICAL 0.85%, HIGH 0.47%, MEDIUM 0.09%, LOW 0.18% |
| Privileges required | NONE 0.46%, LOW 0.21%, HIGH 0.23% |
| Scope | UNCHANGED 0.40%, CHANGED 0.16% |
| Attack vector | NETWORK 0.35%, LOCAL 0.37% (hardly any difference), PHYSICAL 0 of 768 |
| User interaction, attack complexity | Small differences |

**Weakness type (CWE):** the strongest single contrast. Cross-site scripting (CWE-79) has 4 positives in 14,745 CVEs (0.03%) and CSRF (CWE-352) has none in 3,277. Command injection (CWE-78) reaches 0.95%, use-after-free (CWE-416) 0.80% and out-of-bounds write (CWE-787) 0.69%. Some CWEs have very high lift (for example CWE-843, 15 positives in 233), but rest on few positives and should be read as hints.

**Vendor and product:** Microsoft 2.17% (67 of 3,081), Apple 2.37%, Cisco 1.55%, Citrix 10.7% (6 of 56). Windows server and desktop versions, Chrome, iPadOS and network security appliances stand out among products.

**Reporting organisation (CNA, `sourceIdentifier`):** Microsoft's own CNA 2.18% and Apple's 1.81%, whereas WordPress-plugin CNAs (Patchstack, Wordfence, WPScan) have **zero** positives in more than 14,000 CVEs. It has no missing values in any year, which makes it more robust than `main_vendor`.

**Cardinality is the problem:**

| Variable | Levels | Levels with at least one positive |
| --- | --- | --- |
| `cwe` | 638 | 76 |
| `main_vendor` | 11,384 | 81 |
| `main_product` | 19,587 | 145 |
| `sourceIdentifier` | 340 | 53 |

With about 320 positives, we cannot use these as raw dummy variables. Plan: keep the most frequent levels (for example top 30 CWEs, top 50 CNAs) plus "other", or build a **vendor history** (number of earlier KEV entries for that vendor before the CVE's publication date, computed from training data only).

### 4. Variables That Drift or Leak

- **References accumulate over time.** The average number of references falls from 5.9 (2018) to 2.7 (2025), which reflects how long a CVE has existed, not the CVE itself. Reference counts and tags are measured at the snapshot date, not at publication. A reference to an exploit may only appear because exploitation has already happened. We exclude them from the main model and run them as a sensitivity analysis. Still to check: whether references pointing to CISA's own KEV entry are counted (these would contain the label).
- **CVSS versions are era-specific.** Version 2 is available for 50% of 2022 CVEs but only 5 to 12% from 2023. Version 4.0 appears from 2024 (9%, then 25% in 2025). Their high AUCs (up to 0.90) come from tiny, unrepresentative subsets, and missingness acts as a year proxy. We drop them.
- **`lastModified` and `vulnStatus` are excluded** because they change after publication, for example when a CVE is added to KEV.

### 5. Is `n_cpe_matches` a Real Signal?

It beats the CVSS score (AUC 0.81 vs 0.72), so we checked two explanations.

**Check 1: is it just the analysed/unanalysed effect?** No. Among analysed CVEs only, the AUCs barely move.

| Variable | AUC, all CVEs | AUC, analysed only |
| --- | --- | --- |
| `n_cpe_matches` | 0.810 | 0.801 |
| `n_products` | 0.771 | 0.760 |
| `n_references` | 0.732 | 0.720 |
| `cvssV31_score` | 0.719 | 0.719 |

**Check 2: is it just a vendor proxy?** Partly, and it depends on the vendor. Within single vendors (analysed CVEs, dev set):

| Vendor | CVEs | Positives | AUC `n_cpe_matches` | AUC `cvssV31_score` |
| --- | --- | --- | --- | --- |
| Apple | 1,477 | 35 | 0.795 | 0.780 |
| Cisco | 899 | 14 | 0.702 | 0.697 |
| Microsoft | 3,081 | 67 | 0.648 | 0.565 |
| Google | 3,997 | 16 | 0.436 | 0.771 |

The count carries information beyond the vendor name for Apple, Cisco and Microsoft (for Microsoft it clearly beats the CVSS score), but not for Google, where it is below 0.5. These are small samples (14 to 67 positives per vendor), so the AUCs are noisy, and the Google result may reflect how Android entries are recorded. We cannot rule out that NVD adds affected versions later for exploited CVEs.

**Decision?:** keep a log-transformed `n_cpe_matches` as a candidate, let the validation years decide, and state the timing limitation in the report.

### 6. Possible Feature Set

| Variable(s) | Plan |
| --- | --- |
| CVSS v3.1 score and components | Keep (score for the baseline, components for the models) |
| `cwe` | Keep, grouped (top levels plus "other", or parent classes) |
| `sourceIdentifier` | Keep, lumped to top levels plus "other" |
| `main_vendor`, `main_product` | Lump rare levels, or use a time-aware vendor history |
| `n_cpe_matches` (log) | Candidate, judged on validation years |
| `description` | Separate text feature block (TF-IDF or embeddings) |
| References, other CVSS versions, `n_vendors`, `desc_nchar`, `cvssV31_exploitability` | Excluded from the main model |
| `lastModified`, `vulnStatus`, KEV columns | Excluded (leakage) |

### Limitations
- Single-variable AUC ignores interactions, and 319 positives make all estimates noisy.
- Everything above uses the 90-day label. The analysis should be repeated for the "ever on KEV" label and for N = 180 as a robustness check.
- Some variables (CVSS scores, product matches, references) are measured at the snapshot date, not at publication, so the model works with information available after NVD analysis.
- The 2025 test population differs from the training years because of the missing vendor data (section 1).

### Next Step?
to-do: Build baselines (random ranking, CVSS threshold, EPSS, logistic regression on CVSS components) on the restricted population and evaluate them on the validation years before any complex model.
