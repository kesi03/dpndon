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

type TrivyScanner struct {
	binaryPath string
}

type trivyResponse struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Class           string      `json:"Class"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	PkgPath          string               `json:"PkgPath,omitempty"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Title            string               `json:"Title"`
	Severity         string               `json:"Severity"`
	SeveritySource   string               `json:"SeveritySource,omitempty"`
	PrimaryURL       string               `json:"PrimaryURL,omitempty"`
	Description      string               `json:"Description,omitempty"`
	References       []string             `json:"References,omitempty"`
	CVSS             map[string]trivyCVSS `json:"CVSS,omitempty"`
}

type trivyCVSS struct {
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector,omitempty"`
}

type trivySBOMResponse struct {
	SchemaVersion int           `json:"schemaVersion"`
	SerializedAt  string        `json:"serializedAt"`
	Results       []trivyResult `json:"Results"`
}

func NewTrivyScanner(binaryPath string) *TrivyScanner {
	if binaryPath == "" {
		binaryPath = "trivy"
	}
	return &TrivyScanner{binaryPath: binaryPath}
}

func (s *TrivyScanner) ScanFS(ctx context.Context, path string, severity string, scanTypes string) (*models.ScanResult, error) {
	args := []string{"fs", "--format", "json", "--scanners", "vuln"}

	if severity != "" {
		args = append(args, "--severity", strings.ToUpper(severity))
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

	return s.parseOutput(raw, absPath, "fs")
}

func (s *TrivyScanner) ScanImage(ctx context.Context, imageName string, severity string) (*models.ScanResult, error) {
	args := []string{"image", "--format", "json"}

	if severity != "" {
		args = append(args, "--severity", strings.ToUpper(severity))
	}

	args = append(args, imageName)

	raw, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}

	return s.parseOutput(raw, imageName, "image")
}

func (s *TrivyScanner) ScanSBOM(ctx context.Context, sbomPath string) (*models.ScanResult, error) {
	args := []string{"sbom", "--format", "json"}

	absPath, err := filepath.Abs(sbomPath)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	args = append(args, absPath)

	raw, err := s.run(ctx, args)
	if err != nil {
		return nil, err
	}

	return s.parseOutput(raw, absPath, "sbom")
}

func (s *TrivyScanner) GenerateSBOM(ctx context.Context, path string, format string) ([]byte, error) {
	if format == "" {
		format = "cyclonedx"
	}

	args := []string{
		"sbom",
		"--format", format,
		"--output", "-",
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	args = append(args, absPath)

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	output, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy sbom failed (exit %d): %s", exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("run trivy sbom: %w", err)
	}
	return output, nil
}

func (s *TrivyScanner) run(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy failed (exit %d): %s", exitErr.ExitCode(), string(output))
		}
		return nil, fmt.Errorf("run trivy: %w", err)
	}
	return output, nil
}

func (s *TrivyScanner) parseOutput(raw []byte, path, scanType string) (*models.ScanResult, error) {
	var resp trivyResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parse trivy output: %w", err)
	}

	result := &models.ScanResult{
		Source:    models.SourceTrivy,
		Tool:      "trivy",
		ScanType:  scanType,
		Path:      path,
		ScannedAt: time.Now(),
	}

	for _, r := range resp.Results {
		if len(r.Vulnerabilities) == 0 {
			continue
		}
		finding := models.Finding{
			Package: models.Package{
				Name: r.Target,
			},
		}
		for _, v := range r.Vulnerabilities {
			vuln := models.Vulnerability{
				ID:        v.VulnerabilityID,
				Summary:   v.Title,
				Severity:  mapTrivySeverity(v.Severity),
				FixedIn:   v.FixedVersion,
				Reference: v.PrimaryURL,
			}

			if vuln.Reference == "" && len(v.References) > 0 {
				vuln.Reference = v.References[0]
			}

			finding.Vulnerabilities = append(finding.Vulnerabilities, vuln)
			result.TotalVulns++
			severityCount(&result.Summary, vuln.Severity)
		}
		result.Findings = append(result.Findings, finding)
	}

	return result, nil
}

func mapTrivySeverity(sev string) models.Severity {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MEDIUM":
		return models.SeverityMedium
	case "LOW":
		return models.SeverityLow
	default:
		return models.SeverityUnknown
	}
}
