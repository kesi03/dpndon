package scanner

import (
	"testing"

	"github.com/dpndon/dpndon/internal/models"
)

func TestParseScanOutput_SinglePackage(t *testing.T) {
	input := []byte(`{
		"results": [
			{
				"source": {"path": "/app/package.json", "type": "lockfile"},
				"packages": [
					{
						"package": {"name": "lodash", "version": "4.17.19", "ecosystem": "npm"},
						"vulnerabilities": [
							{
								"id": "GHSA-jf85-cpcp-j695",
								"aliases": ["CVE-2021-23337"],
								"summary": "Prototype Pollution in lodash",
								"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
								"references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-jf85-cpcp-j695"}]
							}
						]
					}
				]
			}
		]
	}`)

	s := NewOSVScanner("")
	result, err := s.parseScanOutput(input, "/app", "source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Source != models.SourceOSV {
		t.Errorf("source = %v, want %v", result.Source, models.SourceOSV)
	}
	if result.Tool != "osv-scanner" {
		t.Errorf("tool = %v, want osv-scanner", result.Tool)
	}
	if result.TotalVulns != 1 {
		t.Errorf("totalVulns = %d, want 1", result.TotalVulns)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}

	finding := result.Findings[0]
	if finding.Package.Name != "lodash" {
		t.Errorf("package name = %v, want lodash", finding.Package.Name)
	}
	if finding.Package.Version != "4.17.19" {
		t.Errorf("package version = %v, want 4.17.19", finding.Package.Version)
	}
	if finding.Package.Ecosystem != "npm" {
		t.Errorf("package ecosystem = %v, want npm", finding.Package.Ecosystem)
	}
	if len(finding.Vulnerabilities) != 1 {
		t.Fatalf("vuln count = %d, want 1", len(finding.Vulnerabilities))
	}

	vuln := finding.Vulnerabilities[0]
	if vuln.ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("vuln ID = %v, want GHSA-jf85-cpcp-j695", vuln.ID)
	}
	if len(vuln.Aliases) != 1 || vuln.Aliases[0] != "CVE-2021-23337" {
		t.Errorf("aliases = %v, want [CVE-2021-23337]", vuln.Aliases)
	}
	if vuln.Reference != "https://github.com/advisories/GHSA-jf85-cpcp-j695" {
		t.Errorf("reference = %v, want advisory URL", vuln.Reference)
	}
}

func TestParseScanOutput_EmptyResults(t *testing.T) {
	input := []byte(`{"results": []}`)

	s := NewOSVScanner("")
	result, err := s.parseScanOutput(input, "/app", "source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalVulns != 0 {
		t.Errorf("totalVulns = %d, want 0", result.TotalVulns)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(result.Findings))
	}
}

func TestParseScanOutput_NoVulnerabilities(t *testing.T) {
	input := []byte(`{
		"results": [
			{
				"source": {"path": "/app/go.sum", "type": "lockfile"},
				"packages": [
					{
						"package": {"name": "golang.org/x/net", "version": "v0.23.0", "ecosystem": "Go"},
						"vulnerabilities": []
					}
				]
			}
		]
	}`)

	s := NewOSVScanner("")
	result, err := s.parseScanOutput(input, "/app", "source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalVulns != 0 {
		t.Errorf("totalVulns = %d, want 0", result.TotalVulns)
	}
	if len(result.Findings) != 0 {
		t.Errorf("findings count = %d, want 0", len(result.Findings))
	}
}

func TestParseScanOutput_MultipleVulns(t *testing.T) {
	input := []byte(`{
		"results": [
			{
				"source": {"path": "/app/package.json", "type": "lockfile"},
				"packages": [
					{
						"package": {"name": "minimist", "version": "1.2.5", "ecosystem": "npm"},
						"vulnerabilities": [
							{
								"id": "GHSA-xvch-5gv4-984h",
								"summary": "Prototype Pollution in minimist",
								"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}],
								"references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44906"}]
							},
							{
								"id": "GHSA-7r7v-rhj2-gv4g",
								"summary": "Prototype Pollution in minimist",
								"references": [{"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-7r7v-rhj2-gv4g"}]
							}
						]
					}
				]
			}
		]
	}`)

	s := NewOSVScanner("")
	result, err := s.parseScanOutput(input, "/app", "source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalVulns != 2 {
		t.Errorf("totalVulns = %d, want 2", result.TotalVulns)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings count = %d, want 1", len(result.Findings))
	}
	if len(result.Findings[0].Vulnerabilities) != 2 {
		t.Errorf("vuln count = %d, want 2", len(result.Findings[0].Vulnerabilities))
	}
}

func TestParseScanOutput_FixedInVersion(t *testing.T) {
	input := []byte(`{
		"results": [
			{
				"source": {"path": "/app/go.sum", "type": "lockfile"},
				"packages": [
					{
						"package": {"name": "golang.org/x/net", "version": "v0.0.0-20220225172249-27dd8689420f", "ecosystem": "Go"},
						"vulnerabilities": [
							{
								"id": "GHSA-7r7v-rhj2-gv4g",
								"summary": "Open Redirect",
								"affected": [
									{
										"package": {"name": "golang.org/x/net", "version": "", "ecosystem": "Go"},
										"ranges": [
											{
												"type": "SEMVER",
												"events": [{"introduced": "0"}, {"fixed": "0.7.0"}]
											}
										]
									}
								]
							}
						]
					}
				]
			}
		]
	}`)

	s := NewOSVScanner("")
	result, err := s.parseScanOutput(input, "/app", "source")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vuln := result.Findings[0].Vulnerabilities[0]
	if vuln.FixedIn != "0.7.0" {
		t.Errorf("fixedIn = %v, want 0.7.0", vuln.FixedIn)
	}
}

func TestParseOSVSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    []osvSeverity
		expected models.Severity
	}{
		{
			name:     "critical score string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "CRITICAL"}},
			expected: models.SeverityCritical,
		},
		{
			name:     "high score string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "HIGH"}},
			expected: models.SeverityHigh,
		},
		{
			name:     "medium score string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "MEDIUM"}},
			expected: models.SeverityMedium,
		},
		{
			name:     "moderate score string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "MODERATE"}},
			expected: models.SeverityMedium,
		},
		{
			name:     "low score string",
			input:    []osvSeverity{{Type: "CVSS_V3", Score: "LOW"}},
			expected: models.SeverityLow,
		},
		{
			name:     "empty severity",
			input:    []osvSeverity{},
			expected: models.SeverityUnknown,
		},
		{
			name:     "nil severity",
			input:    nil,
			expected: models.SeverityUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOSVSeverity(tt.input)
			if result != tt.expected {
				t.Errorf("parseOSVSeverity() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSeverityCount(t *testing.T) {
	tests := []struct {
		name     string
		input    models.Severity
		expected models.Summary
	}{
		{"critical", models.SeverityCritical, models.Summary{Critical: 1}},
		{"high", models.SeverityHigh, models.Summary{High: 1}},
		{"medium", models.SeverityMedium, models.Summary{Medium: 1}},
		{"low", models.SeverityLow, models.Summary{Low: 1}},
		{"unknown", models.SeverityUnknown, models.Summary{Unknown: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s models.Summary
			severityCount(&s, tt.input)
			if s != tt.expected {
				t.Errorf("severityCount() = %+v, want %+v", s, tt.expected)
			}
		})
	}
}
