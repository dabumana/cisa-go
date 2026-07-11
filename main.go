package cisa

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultTimeout = 30 * time.Second
)

type Client struct {
	httpClient *http.Client
	baseURL    string
}

type Option func(*Client)

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.baseURL = baseURL }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type Catalog struct {
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID               string   `json:"cveID"`
	VendorProject       string   `json:"vendorProject"`
	Product             string   `json:"product"`
	VulnerabilityName   string   `json:"vulnerabilityName"`
	DateAdded           string   `json:"dateAdded"`
	ShortDescription    string   `json:"shortDescription"`
	RequiredAction      string   `json:"requiredAction"`
	DueDate             string   `json:"dueDate"`
	KnownRansomwareCampaignUse bool `json:"knownRansomwareCampaignUse"`
	Notes               string   `json:"notes"`
	CWEs                []string `json:"cwes"`
}

type Filter struct {
	CveID                   string
	VendorProject           string
	Product                 string
	VulnerabilityName       string
	DateAddedFrom           string
	DateAddedTo             string
	DueDateFrom             string
	DueDateTo               string
	KnownRansomwareCampaignUse *bool
	HasCWE                  string
	Search                  string
}

func (c *Client) GetCatalog() (*Catalog, error) {
	req, err := http.NewRequest("GET", c.baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var catalog Catalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, err
	}

	return &catalog, nil
}

func (c *Client) GetVulnerabilities() ([]Vulnerability, error) {
	catalog, err := c.GetCatalog()
	if err != nil {
		return nil, err
	}
	return catalog.Vulnerabilities, nil
}

func (c *Client) GetVulnerability(cveID string) (*Vulnerability, error) {
	vulns, err := c.GetVulnerabilities()
	if err != nil {
		return nil, err
	}
	for _, v := range vulns {
		if strings.EqualFold(v.CveID, cveID) {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("vulnerability with CVE ID %s not found", cveID)
}

func (c *Client) Filter(filter Filter) ([]Vulnerability, error) {
	vulns, err := c.GetVulnerabilities()
	if err != nil {
		return nil, err
	}

	var results []Vulnerability
	for _, v := range vulns {
		if !matchesFilter(v, filter) {
			continue
		}
		results = append(results, v)
	}
	return results, nil
}

func matchesFilter(v Vulnerability, f Filter) bool {
	if f.CveID != "" && !strings.EqualFold(v.CveID, f.CveID) {
		return false
	}
	if f.VendorProject != "" && !strings.EqualFold(v.VendorProject, f.VendorProject) {
		return false
	}
	if f.Product != "" && !strings.EqualFold(v.Product, f.Product) {
		return false
	}
	if f.VulnerabilityName != "" && !strings.Contains(strings.ToLower(v.VulnerabilityName), strings.ToLower(f.VulnerabilityName)) {
		return false
	}
	if f.DateAddedFrom != "" && v.DateAdded < f.DateAddedFrom {
		return false
	}
	if f.DateAddedTo != "" && v.DateAdded > f.DateAddedTo {
		return false
	}
	if f.DueDateFrom != "" && v.DueDate < f.DueDateFrom {
		return false
	}
	if f.DueDateTo != "" && v.DueDate > f.DueDateTo {
		return false
	}
	if f.KnownRansomwareCampaignUse != nil && v.KnownRansomwareCampaignUse != *f.KnownRansomwareCampaignUse {
		return false
	}
	if f.HasCWE != "" {
		found := false
		for _, cwe := range v.CWEs {
			if strings.Contains(cwe, f.HasCWE) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.Search != "" {
		searchLower := strings.ToLower(f.Search)
		fields := []string{
			v.CveID,
			v.VendorProject,
			v.Product,
			v.VulnerabilityName,
			v.ShortDescription,
			v.Notes,
		}
		found := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), searchLower) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
