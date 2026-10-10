library(jsonlite)
library(dplyr)
library(purrr)
library(readr)

## make sure working directory is set correctly


# ---------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------

# Safe getter: first element, or NA if missing/empty
pick <- function(x, default = NA) {
  if (is.null(x) || length(x) == 0) default else x[[1]]
}

# NVD often lists several CVSS entries per version (e.g. from NVD and from the vendor).
# Prefer the "Primary" entry (= NVD's own assessment), otherwise take the first.
get_metric <- function(metric_list) {
  if (is.null(metric_list) || length(metric_list) == 0) return(NULL)
  types <- map_chr(metric_list, ~ pick(.x$type, ""))
  idx <- if (any(types == "Primary")) which(types == "Primary")[1] else 1
  metric_list[[idx]]
}

# ---------------------------------------------------------------
# One CVE (nested list) -> one row
# ---------------------------------------------------------------
flatten_cve <- function(item) {
  
  # --- English description ---
  desc_en <- NA_character_
  for (d in item$descriptions) {
    if (identical(d$lang, "en")) { desc_en <- d$value; break }
  }
  
  # --- CVSS v3.1 (with the individual components, useful as features) ---
  m31 <- get_metric(item$metrics$cvssMetricV31)
  d31 <- m31$cvssData
  
  # --- other CVSS versions (older CVEs have v2/v3.0, newest have v4.0) ---
  d30 <- get_metric(item$metrics$cvssMetricV30)$cvssData
  d40 <- get_metric(item$metrics$cvssMetricV40)$cvssData
  d2  <- get_metric(item$metrics$cvssMetricV2)$cvssData
  
  # --- CWE: primary one + all of them ---
  cwe_vals <- unlist(map(item$weaknesses, function(w) {
    map_chr(w$description, ~ pick(.x$value, NA_character_))
  }))
  cwe_primary <- pick(cwe_vals, NA_character_)
  cwe_all     <- if (length(cwe_vals)) paste(unique(cwe_vals), collapse = "|") else NA_character_
  
  # --- Vendor / product from CPE strings (configurations) ---
  # CPE format: cpe:2.3:<part>:<vendor>:<product>:<version>:...
  cpe_strings <- unlist(map(item$configurations, function(cfg) {
    map(cfg$nodes, function(nd) {
      map(nd$cpeMatch, function(m) if (isTRUE(m$vulnerable)) m$criteria else NULL)
    })
  }))
  if (length(cpe_strings) > 0) {
    parts    <- strsplit(cpe_strings, ":", fixed = TRUE)
    vendors  <- map_chr(parts, ~ pick(.x[4], NA_character_))
    products <- map_chr(parts, ~ pick(.x[5], NA_character_))
    main_vendor     <- names(sort(table(vendors), decreasing = TRUE))[1]
    main_product    <- names(sort(table(products), decreasing = TRUE))[1]
    n_vendors       <- length(unique(vendors))
    n_products      <- length(unique(products))
    n_cpe_matches   <- length(cpe_strings)
  } else {
    main_vendor <- main_product <- NA_character_
    n_vendors <- n_products <- n_cpe_matches <- 0L
  }
  
  # --- References: count and tags ---
  refs     <- item$references
  ref_tags <- unlist(map(refs, ~ unlist(.x$tags)))
  
  tibble(
    id                = pick(item$id),
    sourceIdentifier  = pick(item$sourceIdentifier),
    published         = pick(item$published),
    lastModified      = pick(item$lastModified),
    vulnStatus        = pick(item$vulnStatus),
    description       = desc_en,
    
    # KEV label (these fields only exist for CVEs on CISA's KEV list)
    kev_date_added    = pick(item$cisaExploitAdd),
    is_kev            = !is.null(item$cisaExploitAdd),
    
    # CVSS v3.1
    cvssV31_score          = pick(d31$baseScore),
    cvssV31_severity       = pick(d31$baseSeverity),
    cvssV31_attackVector   = pick(d31$attackVector),
    cvssV31_attackComplex  = pick(d31$attackComplexity),
    cvssV31_privReq        = pick(d31$privilegesRequired),
    cvssV31_userInteract   = pick(d31$userInteraction),
    cvssV31_scope          = pick(d31$scope),
    cvssV31_confImpact     = pick(d31$confidentialityImpact),
    cvssV31_integImpact    = pick(d31$integrityImpact),
    cvssV31_availImpact    = pick(d31$availabilityImpact),
    cvssV31_exploitability = pick(m31$exploitabilityScore),
    cvssV31_impact         = pick(m31$impactScore),
    
    # other CVSS versions (scores only)
    cvssV30_score = pick(d30$baseScore),
    cvssV40_score = pick(d40$baseScore),
    cvssV2_score  = pick(d2$baseScore),
    
    # weakness type
    cwe     = cwe_primary,
    cwe_all = cwe_all,
    
    # product information
    main_vendor   = main_vendor,
    main_product  = main_product,
    n_vendors     = n_vendors,
    n_products    = n_products,
    n_cpe_matches = n_cpe_matches,
    
    # references
    n_references      = length(refs),
    n_ref_exploit_tag = sum(ref_tags == "Exploit"),
    n_ref_patch_tag   = sum(ref_tags == "Patch")
  )
}


files <- list.files(pattern = "^nvdcve-2\\.0-\\d{4}\\.json$", full.names = TRUE)
stopifnot("No NVD json files found - check getwd()" = length(files) > 0)
print(files)

nvd_all <- map_dfr(files, function(f) {
  cat("Importing", f, "...\n")
  raw  <- fromJSON(f, simplifyVector = FALSE)
  cves <- compact(map(raw$vulnerabilities, ~ .x$cve))
  cat("  CVE records:", length(cves), "\n")
  map_dfr(cves, flatten_cve)
})

print(dim(nvd_all))
print(table(nvd_all$is_kev))

write_csv(nvd_all, "NVD_all.csv")
message("Exported NVD_all.csv to: ", getwd())