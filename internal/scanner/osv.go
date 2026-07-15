package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dpndon/dpndon/internal/models"
)

type OSVScanner struct {
	binaryPath string
}

type osvResponse struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource    `json:"source"`
	Packages []osvPackage `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPackage struct {
	Package         osvPkgInfo `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
	Groups          []osvGroup `json:"groups,omitempty"`
}

type osvPkgInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVuln struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases,omitempty"`
	Summary    string         `json:"summary,omitempty"`
	Severity   []osvSeverity  `json:"severity,omitempty"`
	FixedIn    []osvFixedIn   `json:"affected,omitempty"`
	References []osvReference `json:"references,omitempty"`
	Published  string         `json:"published,omitempty"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvFixedIn struct {
	Package osvPkgInfo `json:"package"`
	Ranges  []struct {
		Type   string `json:"type"`
		Events []struct {
			Fixed string `json:"fixed,omitempty"`
		} `json:"events"`
	} `json:"ranges"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvGroup struct {
	IDs []string `json:"ids"`
}

func NewOSVScanner(binaryPath string) *OSVScanner {
	if binaryPath == "" {
		binaryPath = "osv-scanner"
	}
	return &OSVScanner{binaryPath: binaryPath}
}

func (s *OSVScanner) ScanSource(ctx context.Context, path string, recursive bool) (*models.ScanResult, error) {
	args := []string{"scan", "source", "--format", "json"}

	if recursive {
		args = append(args, "--recursive")
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	args = append(args, absPath)

	raw, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}

	return s.parseScanOutput(raw, absPath, "source")
}

func (s *OSVScanner) ScanImage(ctx context.Context, imageName string) (*models.ScanResult, error) {
	args := []string{"scan", "image", "--format", "json", imageName}

	raw, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}

	return s.parseScanOutput(raw, imageName, "image")
}

func (s *OSVScanner) LookupVulnerability(ctx context.Context, vulnID string) (map[string]any, error) {
	args := []string{"--format", "json", "vulnerability", vulnID}
	raw, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("parse vulnerability lookup: %w", err)
	}
	return result, nil
}

func (s *OSVScanner) run(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("osv-scanner failed (exit %d): %s", exitErr.ExitCode(), string(output))
		}
		return nil, fmt.Errorf("run osv-scanner: %w", err)
	}
	return output, nil
}

func (s *OSVScanner) parseScanOutput(raw []byte, path, scanType string) (*models.ScanResult, error) {
	var resp osvResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse osv-scanner output: %w", err)
	}

	result := &models.ScanResult{
		Source:    models.SourceOSV,
		Tool:      "osv-scanner",
		ScanType:  scanType,
		Path:      path,
		ScannedAt: time.Now(),
	}

	for _, r := range resp.Results {
		for _, pkg := range r.Packages {
			finding := models.Finding{
				Package: models.Package{
					Name:      pkg.Package.Name,
					Version:   pkg.Package.Version,
					Ecosystem: pkg.Package.Ecosystem,
				},
			}

			for _, v := range pkg.Vulnerabilities {
				vuln := models.Vulnerability{
					ID:          v.ID,
					Aliases:     v.Aliases,
					Summary:     v.Summary,
					Severity:    parseOSVSeverity(v.Severity),
					PublishedAt: v.Published,
				}

				for _, ref := range v.References {
					if ref.Type == "ADVISORY" || ref.Type == "WEB" {
						vuln.Reference = ref.URL
						break
					}
				}

				for _, aff := range v.FixedIn {
					for _, rng := range aff.Ranges {
						for _, evt := range rng.Events {
							if evt.Fixed != "" {
								vuln.FixedIn = evt.Fixed
								break
							}
						}
					}
				}

				finding.Vulnerabilities = append(finding.Vulnerabilities, vuln)
				result.TotalVulns++
				severityCount(&result.Summary, vuln.Severity)
			}

			if len(finding.Vulnerabilities) > 0 {
				result.Findings = append(result.Findings, finding)
			}
		}
	}

	return result, nil
}

func parseOSVSeverity(sevs []osvSeverity) models.Severity {
	for _, s := range sevs {
		score := strings.ToUpper(s.Score)
		switch {
		case strings.Contains(score, "CRITICAL"):
			return models.SeverityCritical
		case strings.Contains(score, "HIGH"):
			return models.SeverityHigh
		case strings.Contains(score, "MEDIUM") || strings.Contains(score, "MODERATE"):
			return models.SeverityMedium
		case strings.Contains(score, "LOW"):
			return models.SeverityLow
		}
	}

	for _, s := range sevs {
		if s.Type == "CVSS_V3" {
			return cvssToSeverity(s.Score)
		}
	}

	return models.SeverityUnknown
}

func cvssToSeverity(score string) models.Severity {
	parts := strings.Split(score, "/")
	for _, part := range parts {
		if strings.HasPrefix(part, "CVSS:") {
			return models.SeverityMedium
		}
	}
	return models.SeverityUnknown
}

func severityCount(s *models.Summary, sev models.Severity) {
	switch sev {
	case models.SeverityCritical:
		s.Critical++
	case models.SeverityHigh:
		s.High++
	case models.SeverityMedium:
		s.Medium++
	case models.SeverityLow:
		s.Low++
	default:
		s.Unknown++
	}
}
