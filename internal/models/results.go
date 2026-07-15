package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityUnknown  Severity = "UNKNOWN"
)

type Source string

const (
	SourceOSV    Source = "osv-scanner"
	SourceTrivy  Source = "trivy"
	SourceDTrack Source = "dependency-track"
)

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl,omitempty"`
}

type Vulnerability struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Severity    Severity `json:"severity"`
	FixedIn     string   `json:"fixed_in,omitempty"`
	Reference   string   `json:"reference,omitempty"`
	PublishedAt string   `json:"published_at,omitempty"`
}

type Finding struct {
	Package         Package         `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type ScanResult struct {
	Source     Source    `json:"source"`
	Tool       string    `json:"tool"`
	ScanType   string    `json:"scan_type"`
	Path       string    `json:"path"`
	ScannedAt  time.Time `json:"scanned_at"`
	Findings   []Finding `json:"findings"`
	TotalVulns int       `json:"total_vulns"`
	Summary    Summary   `json:"summary"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type Project struct {
	UUID            string `json:"uuid"`
	Name            string `json:"name"`
	Version         string `json:"version,omitempty"`
	PURL            string `json:"purl,omitempty"`
	Active          bool   `json:"active"`
	Vulnerabilities int    `json:"vulnerabilities"`
}

type DTrackFinding struct {
	Component     Component `json:"component"`
	Vulnerability VulnInfo  `json:"vulnerability"`
	Analysis      *Analysis `json:"analysis,omitempty"`
}

type Component struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type VulnInfo struct {
	VulnID    string   `json:"vulnId"`
	Title     string   `json:"title,omitempty"`
	Severity  Severity `json:"severity"`
	CVSSScore float64  `json:"cvssScore,omitempty"`
	Aliases   []string `json:"aliases,omitempty"`
}

type Analysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Comment       string `json:"comment,omitempty"`
}

type DTrackMetrics struct {
	Projects             int `json:"projects"`
	VulnerableProjects   int `json:"vulnerableProjects"`
	TotalVulnerabilities int `json:"totalVulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Unassigned           int `json:"unassigned"`
}
