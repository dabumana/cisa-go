# CISA KEV - Go Client

A Go client for the CISA Known Exploited Vulnerabilities (KEV) Catalog, a feed of vulnerabilities that are known to be actively exploited in the wild.
This package provides a simple, idiomatic way to fetch, search, and filter the official CISA JSON feed.

---

## Installation

```bash
go get github.com/dabumana/cisa-go
```

Replace with your actual module path if publishing.

### Quick Start

```go
package main

import (
    "fmt"
    "log"
    "cisakev"
)

func main() {
    client := cisa.NewClient()
    catalog, err := client.GetCatalog()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Catalog version: %s, entries: %d\n", catalog.CatalogVersion, catalog.Count)
}
```

---

## Authentication

No authentication is required - the feed is publicly available.

### Client Configuration

You can customise the client with optional Option functions:

### Option Description
WithHTTPClient(*http.Client) Use a custom HTTP client (e.g., for proxies, custom timeouts).
WithBaseURL(string) Override the base URL (useful for testing or mirrors).

Example:

```go
customClient := &http.Client{Timeout: 10 * time.Second}
client := cisa.NewClient(
    cisa.WithHTTPClient(customClient),
    cisa.WithBaseURL("https://example.com/feed.json"),
)
```

## API Methods

|Method | Description|
|-------|------------|
|GetCatalog() (*Catalog, error) | Returns the full catalog (all fields).|
|GetVulnerabilities() ([]Vulnerability, error) | Returns only the list of vulnerabilities.|
|GetVulnerability(cveID string) (*Vulnerability, error) | Finds a specific CVE by its ID (case‑insensitive).|
|Filter(filter Filter) ([]Vulnerability, error) | Applies multiple filters to the catalog.|

### Data Types

* Catalog - The full feed, containing CatalogVersion, DateReleased, Count, and a slice of Vulnerability.
* Vulnerability - A single entry with fields:
  * CveID - e.g., CVE-2024-12345
  * VendorProject - affected vendor
  * Product - affected product
  * VulnerabilityName - brief name
  * DateAdded - when CISA added it (YYYY-MM-DD)
  * ShortDescription - description
  * RequiredAction - e.g., "Apply updates"
  * DueDate - remediation deadline
  * KnownRansomwareCampaignUse – boolean
  * Notes - additional notes
  * CWEs - list of CWE identifiers
* Filter - struct for advanced search (see below).

### Filtering

The Filter struct allows you to search the catalog with the following fields (all optional):

|Field | Type | Description|
|------|------|------------|
|CveID | string | Exact CVE ID (case‑insensitive).|
|VendorProject | string | Exact vendor name (case‑insensitive).|
|Product | string | Exact product name (case‑insensitive).|
|VulnerabilityName | string | Substring match (case‑insensitive).|
|DateAddedFrom | string | Lower bound (YYYY-MM-DD).|
|DateAddedTo | string | Upper bound (YYYY-MM-DD).|
|DueDateFrom | string | Lower bound (YYYY-MM-DD).|
|DueDateTo | string | Upper bound (YYYY-MM-DD).|
|KnownRansomwareCampaignUse | *bool | Filter by ransomware flag.|
|HasCWE | string | Substring match in CWEs (e.g., "CWE-79").|
|Search | string | Full‑text search across CVE ID, vendor, product, name, description, and notes.|

All text filters are case‑insensitive.

### Error Handling

The client returns standard Go errors.
Common errors:

* Network failures.
* HTTP status non‑200 (e.g., 404 if the feed URL changes).
* JSON unmarshalling errors.

You can inspect the error type for more details, but generally a simple if err != nil check suffices.

### Examples

1. Get the Full Catalog

```go
client := cisa.NewClient()
catalog, err := client.GetCatalog()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d vulnerabilities\n", catalog.Count)
```

2. Fetch All Vulnerabilities

```go
vulns, err := client.GetVulnerabilities()
if err != nil {
    log.Fatal(err)
}
for _, v := range vulns {
    fmt.Printf("%s: %s\n", v.CveID, v.ShortDescription)
}
```

3. Get a Specific CVE

```go
vuln, err := client.GetVulnerability("CVE-2024-6387")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Vendor: %s, Product: %s\n", vuln.VendorProject, vuln.Product)
```

4. Filter by Vendor and Ransomware Use

```go
ransom := true
filter := cisa.Filter{
    VendorProject: "Microsoft",
    KnownRansomwareCampaignUse: &ransom,
}
results, err := client.Filter(filter)
if err != nil {
    log.Fatal(err)
}
for _, v := range results {
    fmt.Printf("%s - due by %s\n", v.CveID, v.DueDate)
}
```

5. Full‑Text Search

```go
filter := cisa.Filter{
    Search: "remote code execution",
}
results, err := client.Filter(filter)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d matching entries\n", len(results))
```

6. Filter by Date Added Range

```go
filter := cisa.Filter{
    DateAddedFrom: "2024-06-01",
    DateAddedTo:   "2024-06-30",
}
results, err := client.Filter(filter)
// ...
```

---

## Important Notes

* Feed freshness - CISA updates the KEV catalog periodically. The client fetches the latest version on each call.
* Time zones - All date fields are in the YYYY-MM-DD format (UTC).
* Rate limits - No authentication or rate limits apply.
