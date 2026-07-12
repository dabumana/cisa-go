package cisakev

import (
        "net/http"
	"os"
	"testing"
)

func liveClient() *Client {
	return NewClient()
}

func requireLive(t *testing.T) {
	t.Helper()
	if os.Getenv("LIVE_TESTS") != "1" {
		t.Skip("set LIVE_TESTS=1 to run live endpoint tests")
	}
}

func TestNewClient(t *testing.T) {
	c := NewClient()
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
	if c.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if c.baseURL == "" {
		t.Fatal("baseURL is empty")
	}
}

func TestWithHTTPClient(t *testing.T) {
	hc := &http.Client{}
	c := NewClient(WithHTTPClient(hc))
	if c.httpClient != hc {
		t.Fatal("WithHTTPClient not applied")
	}
}

func TestWithBaseURL(t *testing.T) {
	u := "https://example.com/test.json"
	c := NewClient(WithBaseURL(u))
	if c.baseURL != u {
		t.Fatalf("baseURL = %q, want %q", c.baseURL, u)
	}
}

func TestGetCatalog(t *testing.T) {
	requireLive(t)

	c := liveClient()
	cat, err := c.GetCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if cat == nil {
		t.Fatal("nil catalog")
	}
}

func TestGetVulnerabilities(t *testing.T) {
	requireLive(t)

	c := liveClient()
	vulns, err := c.GetVulnerabilities()
	if err != nil {
		t.Fatal(err)
	}
	if vulns == nil {
		t.Fatal("nil vulnerabilities")
	}
}

func TestGetVulnerability(t *testing.T) {
	requireLive(t)

	c := liveClient()
	vulns, err := c.GetVulnerabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) == 0 {
		t.Fatal("no vulnerabilities returned")
	}

	got, err := c.GetVulnerability(vulns[0].CveID)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("nil vulnerability")
	}
}

func TestFilter(t *testing.T) {
	requireLive(t)

	c := liveClient()
	vulns, err := c.GetVulnerabilities()
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) == 0 {
		t.Fatal("no vulnerabilities returned")
	}

	got, err := c.Filter(Filter{CveID: vulns[0].CveID})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("expected filtered results")
	}
}

func TestMatchesFilter(t *testing.T) {
	v := Vulnerability{
		CveID:                 "CVE-2024-0001",
		VendorProject:         "Acme",
		Product:               "Widget",
		VulnerabilityName:     "Test Vuln",
		DateAdded:             "2024-01-01",
		DueDate:               "2024-02-01",
		KnownRansomwareCampaignUse: "true",
		ShortDescription:      "desc",
		Notes:                 "note",
		CWEs:                  []string{"CWE-79"},
	}

	if !matchesFilter(v, Filter{}) {
		t.Fatal("empty filter should match")
	}
	if matchesFilter(v, Filter{CveID: "other"}) {
		t.Fatal("unexpected match")
	}
}
