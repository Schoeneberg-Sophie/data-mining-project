library(dplyr)
library(purrr)
library(readr)
library(tidyr)

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


sum(!is.na(nvd_all$kev_date_added))   # should equal the number of TRUE rows (1,220)
sum(nvd_all$is_kev)

# label splits
nvd_all <- read_csv("NVD_all.csv")

# Snapshot date = latest modification date in the data
snapshot <- as.Date(substr(as.character(max(nvd_all$lastModified)), 1, 10))
N <- 90   # label window in days (try 180 as robustness check)
nvd_model <- nvd_all %>%
  mutate(
    published_d = as.Date(substr(as.character(published), 1, 10)),
    year        = as.integer(format(published_d, "%Y")),
    days_to_kev = as.numeric(as.Date(kev_date_added) - published_d),
    
    # Label A: listed on KEV at any point up to the snapshot
    label_ever  = is_kev,
    
    # Label B: listed within N days of publication (NA in kev_date_added -> FALSE)
    label_90d   = !is.na(days_to_kev) & days_to_kev <= N,
    
    # Only CVEs whose N-day window is fully observed may use label B
    eligible_90d = published_d <= snapshot - N
  )


#Overview per year (sanity check before modeling)

nvd_model %>%
  group_by(year) %>%
  summarise(
    n            = n(),
    pos_ever     = sum(label_ever),
    pos_90d      = sum(label_90d & eligible_90d),
    n_eligible   = sum(eligible_90d),
    .groups = "drop"
  ) %>%
  print(n = Inf)


#experiments (test year is always 2025)
experiments <- list(
  A_ever_2022_24 = list(train_years = 2022:2024, label = "label_ever"),
  B_ever_2018_24 = list(train_years = 2018:2024, label = "label_ever"),
  C_90d_2022_24  = list(train_years = 2022:2024, label = "label_90d")
)

get_split <- function(e, test_year = 2025) {
  d <- if (e$label == "label_90d") filter(nvd_model, eligible_90d) else nvd_model
  list(
    train = filter(d, year %in% e$train_years),
    test  = filter(d, year == test_year),
    label = e$label
  )
}

# Rolling validation inside the training period (tune on these, NOT on 2025):
#   train up to 2022 -> validate 2023;  train up to 2023 -> validate 2024
get_folds <- function(e) {
  first <- min(e$train_years)
  d <- if (e$label == "label_90d") filter(nvd_model, eligible_90d) else nvd_model
  list(
    list(train = filter(d, year %in% first:2022),
         valid = filter(d, year == 2023)),
    list(train = filter(d, year %in% first:2023),
         valid = filter(d, year == 2024))
  )
}

# Class counts per experiment
imap_dfr(experiments, function(e, nm) {
  s <- get_split(e)
  tibble(
    experiment = nm,
    n_train    = nrow(s$train),
    pos_train  = sum(s$train[[s$label]]),
    n_test     = nrow(s$test),
    pos_test   = sum(s$test[[s$label]])
  )
}) %>% print()

# columns that must NOT be used as features (label leakage)
leak_cols <- c(
  "kev_date_added", "is_kev", "days_to_kev",
  "label_ever", "label_90d", "eligible_90d",
  "lastModified",   # changes when a CVE is added to KEV
  "vulnStatus"      # analysis status is updated after publication
)

# Example: features for experiment C
# s <- get_split(experiments$C_90d_2022_24)
# x_train <- s$train %>% select(-all_of(leak_cols), -id, -published, -published_d)
# y_train <- s$train[[s$label]]


# feature eval
# setup: labels and DEVELOPMENT set (training years only)
#    Never look at 2025 here, otherwise feature choices leak the test set.
nvd <- read_csv("NVD_all.csv", show_col_types = FALSE)

snapshot <- as.Date(substr(as.character(max(nvd$lastModified)), 1, 10))
N <- 90   # label window; change to 180 as a robustness check

nvd <- nvd %>%
  mutate(
    published_d = as.Date(substr(as.character(published), 1, 10)),
    year        = as.integer(format(published_d, "%Y")),
    days_to_kev = as.numeric(as.Date(kev_date_added) - published_d),
    label       = !is.na(days_to_kev) & days_to_kev <= N,
    eligible    = published_d <= snapshot - N,
    desc_nchar  = nchar(description)          # simple text feature
  )

dev_years <- 2022:2024
dev_set   <- nvd %>% filter(eligible, year %in% dev_years)
base_rate <- mean(dev_set$label)
cat("Development set:", nrow(dev_set), "CVEs,", sum(dev_set$label),
    "positives, base rate", round(100 * base_rate, 2), "%\n")

num_vars <- c(
  "cvssV31_score", "cvssV31_exploitability", "cvssV31_impact",
  "cvssV30_score", "cvssV40_score", "cvssV2_score",
  "n_vendors", "n_products", "n_cpe_matches",
  "n_references", "n_ref_exploit_tag", "n_ref_patch_tag",
  "desc_nchar"
)
cat_vars <- c(
  "cvssV31_severity", "cvssV31_attackVector", "cvssV31_attackComplex",
  "cvssV31_privReq", "cvssV31_userInteract", "cvssV31_scope",
  "cvssV31_confImpact", "cvssV31_integImpact", "cvssV31_availImpact",
  "cwe", "main_vendor", "main_product", "sourceIdentifier"
)

# AUC via ranks (0.5 = no signal, >0.5 = higher value -> more likely KEV)
auc_rank <- function(x, y) {
  ok <- !is.na(x) & !is.na(y)
  x <- x[ok]; y <- y[ok]
  n1 <- sum(y); n0 <- sum(!y)
  if (n1 == 0 || n0 == 0 || length(unique(x)) < 2) return(NA_real_)
  (sum(rank(x)[y]) - n1 * (n1 + 1) / 2) / (n1 * n0)
}


# 1. Missingness by publication year (all years since 2018)
cat("\n=== 1. Share of missing values per variable and year ===\n")
nvd %>%
  filter(year >= 2018, year <= 2025) %>%
  group_by(year) %>%
  summarise(across(all_of(c(num_vars, cat_vars)), ~ round(mean(is.na(.x)), 3))) %>%
  pivot_longer(-year, names_to = "variable", values_to = "missing") %>%
  pivot_wider(names_from = year, values_from = missing) %>%
  print(n = Inf)


# Numeric variables: signal, missingness, stability over years
cat("\n=== 2. Numeric variables (development years only) ===\n")
num_eval <- map_dfr(num_vars, function(v) {
  tibble(
    variable      = v,
    missing_share = round(mean(is.na(dev_set[[v]])), 3),
    n_distinct    = n_distinct(dev_set[[v]]),
    auc           = round(auc_rank(dev_set[[v]], dev_set$label), 3),
    # Is the MISSINGNESS itself predictive? (can reveal an era effect)
    auc_missing   = round(auc_rank(as.numeric(is.na(dev_set[[v]])), dev_set$label), 3)
  )
})

auc_by_year <- map_dfr(dev_years, function(yr) {
  d <- filter(dev_set, year == yr)
  tibble(year = yr, variable = num_vars,
         auc = round(map_dbl(num_vars, ~ auc_rank(d[[.x]], d$label)), 3))
}) %>% pivot_wider(names_from = year, values_from = auc, names_prefix = "auc_")

num_eval %>%
  left_join(auc_by_year, by = "variable") %>%
  mutate(signal = round(abs(auc - 0.5), 3)) %>%
  arrange(desc(signal)) %>%
  print(n = Inf)

#Categorical variables: cardinality and coverage
cat("\n=== 3. Categorical variables: cardinality ===\n")
cat_summary <- map_dfr(cat_vars, function(v) {
  tb <- sort(table(dev_set[[v]]), decreasing = TRUE)
  pos_by_level <- tapply(dev_set$label, dev_set[[v]], sum)
  tibble(
    variable            = v,
    missing_share       = round(mean(is.na(dev_set[[v]])), 3),
    n_levels            = length(tb),
    top20_row_share     = round(sum(tb[seq_len(min(20, length(tb)))]) / sum(tb), 3),
    levels_with_positive = sum(pos_by_level > 0, na.rm = TRUE)
  )
})
print(cat_summary, n = Inf)


#Categorical variables II: positive rate per level

level_table <- function(v, top = 15, min_n = 30, by = c("n", "lift")) {
  by <- match.arg(by)
  out <- dev_set %>%
    group_by(level = .data[[v]]) %>%
    summarise(n = n(), positives = sum(label), rate = mean(label), .groups = "drop") %>%
    mutate(lift = round(rate / base_rate, 2), rate = round(100 * rate, 2)) %>%
    filter(n >= min_n)
  if (by == "n") arrange(out, desc(n)) %>% slice_head(n = top)
  else           arrange(out, desc(lift)) %>% slice_head(n = top)
}

cat("\n=== 4. Positive rate (%) and lift per level ===\n")
# Low-cardinality variables: print every level
for (v in c("cvssV31_attackVector", "cvssV31_attackComplex", "cvssV31_privReq",
            "cvssV31_userInteract", "cvssV31_scope", "cvssV31_severity")) {
  cat("\n--", v, "--\n")
  print(level_table(v, top = 20), n = Inf)
}
# High-cardinality variables: most frequent levels and highest-lift levels
for (v in c("cwe", "main_vendor", "main_product", "sourceIdentifier")) {
  cat("\n--", v, ": most frequent levels --\n")
  print(level_table(v, by = "n"), n = Inf)
  cat("\n--", v, ": highest lift (n >= 30) --\n")
  print(level_table(v, by = "lift"), n = Inf)
}


# Redundancy between numeric variables (Spearman's correlation)

cat("\n=== 5. Spearman correlations ===\n")
print(round(cor(dev_set[, num_vars], use = "pairwise.complete.obs",
                method = "spearman"), 2))


#(Era effects) which fields exist in which year?
cat("\n=== 6. Availability and drift by year ===\n")
nvd %>%
  filter(year >= 2018, year <= 2025) %>%
  group_by(year) %>%
  summarise(
    has_v2          = round(mean(!is.na(cvssV2_score)), 3),
    has_v30         = round(mean(!is.na(cvssV30_score)), 3),
    has_v31         = round(mean(!is.na(cvssV31_score)), 3),
    has_v40         = round(mean(!is.na(cvssV40_score)), 3),
    has_vendor      = round(mean(!is.na(main_vendor)), 3),
    mean_references = round(mean(n_references), 2),
    share_exploit_ref = round(mean(n_ref_exploit_tag > 0), 3)
  ) %>%
  print(n = Inf)

#checks
#development years: structural pattern of analysed/unanalyse effects?
analysed <- dev_set %>% filter(!is.na(cvssV31_score))
#Positives among unanalysed CVEs, per development year
dev_set %>% group_by(year) %>%
  summarise(pos = sum(label),
            pos_no_cvss   = sum(label & is.na(cvssV31_score)),
            pos_no_vendor = sum(label & is.na(main_vendor)))
#Redo the AUCs among analysed CVEs only
map_dbl(c("n_cpe_matches", "n_products", "n_references", "cvssV31_score"),
        ~ auc_rank(analysed[[.x]], analysed$label))

#vendor proxy?
analysed <- dev_set %>% filter(!is.na(cvssV31_score), !is.na(main_vendor))
analysed %>%
  filter(main_vendor %in% c("microsoft", "apple", "google", "cisco")) %>%
  group_by(main_vendor) %>%
  summarise(n = n(), pos = sum(label),
            auc_cpe  = auc_rank(n_cpe_matches, label),
            auc_cvss = auc_rank(cvssV31_score, label))