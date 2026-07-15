package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dpndon/dpndon/internal/models"
)

type DTrackClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type dtrackProjectsResponse []struct {
	UUID            string `json:"uuid"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	PURL            string `json:"purl,omitempty"`
	Active          bool   `json:"active"`
	Vulnerabilities struct {
		Total int `json:"total"`
	} `json:"vulnerabilities"`
}

type dtrackFindingsResponse []struct {
	Component struct {
		UUID    string `json:"uuid"`
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl,omitempty"`
		CPE     string `json:"cpe,omitempty"`
	} `json:"component"`
	Vulnerability struct {
		VulnID    string  `json:"vulnId"`
		Title     string  `json:"title"`
		Severity  string  `json:"severity"`
		CVSSScore float64 `json:"cvssScore,omitempty"`
	} `json:"vulnerability"`
	Analysis *struct {
		State         string `json:"state"`
		Justification string `json:"justification,omitempty"`
		Comment       string `json:"comment,omitempty"`
	} `json:"analysis,omitempty"`
}

type dtrackMetricsResponse struct {
	Projects             int `json:"projects"`
	VulnerableProjects   int `json:"vulnerableProjects"`
	TotalVulnerabilities int `json:"totalVulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Unassigned           int `json:"unassigned"`
}

type dtrackErrorResponse struct {
	Message string `json:"message"`
}

func NewDTrackClient(baseURL, apiKey string) *DTrackClient {
	return &DTrackClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *DTrackClient) ListProjects(ctx context.Context, query string, page, pageSize int) ([]models.Project, error) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 25
	}

	url := fmt.Sprintf("%s/api/v1/project?pageSize=%d&page=%d", c.baseURL, pageSize, page)
	if query != "" {
		url += "&searchText=" + query
	}

	var projects dtrackProjectsResponse
	if err := c.get(ctx, url, &projects); err != nil {
		return nil, err
	}

	var result []models.Project
	for _, p := range projects {
		result = append(result, models.Project{
			UUID:            p.UUID,
			Name:            p.Name,
			Version:         p.Version,
			PURL:            p.PURL,
			Active:          p.Active,
			Vulnerabilities: p.Vulnerabilities.Total,
		})
	}
	return result, nil
}

func (c *DTrackClient) ListFindings(ctx context.Context, projectUUID string, severity string) ([]models.DTrackFinding, error) {
	url := fmt.Sprintf("%s/api/v1/finding/project/%s", c.baseURL, projectUUID)
	if severity != "" {
		url += "?severity=" + strings.ToUpper(severity)
	}

	var findings dtrackFindingsResponse
	if err := c.get(ctx, url, &findings); err != nil {
		return nil, err
	}

	var result []models.DTrackFinding
	for _, f := range findings {
		df := models.DTrackFinding{
			Component: models.Component{
				UUID:    f.Component.UUID,
				Name:    f.Component.Name,
				Version: f.Component.Version,
				PURL:    f.Component.PURL,
				CPE:     f.Component.CPE,
			},
			Vulnerability: models.VulnInfo{
				VulnID:    f.Vulnerability.VulnID,
				Title:     f.Vulnerability.Title,
				Severity:  mapDTrackSeverity(f.Vulnerability.Severity),
				CVSSScore: f.Vulnerability.CVSSScore,
			},
		}

		if f.Analysis != nil {
			df.Analysis = &models.Analysis{
				State:         f.Analysis.State,
				Justification: f.Analysis.Justification,
				Comment:       f.Analysis.Comment,
			}
		}

		result = append(result, df)
	}
	return result, nil
}

func (c *DTrackClient) SearchVulnerability(ctx context.Context, query string) ([]models.VulnInfo, error) {
	url := fmt.Sprintf("%s/api/v1/vulnerability?searchText=%s", c.baseURL, query)

	var vulns []struct {
		VulnID    string   `json:"vulnId"`
		Title     string   `json:"title"`
		Severity  string   `json:"severity"`
		CVSSScore float64  `json:"cvssScore,omitempty"`
		Aliases   []string `json:"aliases,omitempty"`
	}
	if err := c.get(ctx, url, &vulns); err != nil {
		return nil, err
	}

	var result []models.VulnInfo
	for _, v := range vulns {
		result = append(result, models.VulnInfo{
			VulnID:    v.VulnID,
			Title:     v.Title,
			Severity:  mapDTrackSeverity(v.Severity),
			CVSSScore: v.CVSSScore,
			Aliases:   v.Aliases,
		})
	}
	return result, nil
}

func (c *DTrackClient) GetPortfolioMetrics(ctx context.Context) (*models.DTrackMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/metrics/portfolio", c.baseURL)

	var m dtrackMetricsResponse
	if err := c.get(ctx, url, &m); err != nil {
		return nil, err
	}

	return &models.DTrackMetrics{
		Projects:             m.Projects,
		VulnerableProjects:   m.VulnerableProjects,
		TotalVulnerabilities: m.TotalVulnerabilities,
		Critical:             m.Critical,
		High:                 m.High,
		Medium:               m.Medium,
		Low:                  m.Low,
		Unassigned:           m.Unassigned,
	}, nil
}

func (c *DTrackClient) GetProjectMetrics(ctx context.Context, projectUUID string) (*models.DTrackMetrics, error) {
	url := fmt.Sprintf("%s/api/v1/metrics/project/%s", c.baseURL, projectUUID)

	var m dtrackMetricsResponse
	if err := c.get(ctx, url, &m); err != nil {
		return nil, err
	}

	return &models.DTrackMetrics{
		Projects:             m.Projects,
		VulnerableProjects:   m.VulnerableProjects,
		TotalVulnerabilities: m.TotalVulnerabilities,
		Critical:             m.Critical,
		High:                 m.High,
		Medium:               m.Medium,
		Low:                  m.Low,
		Unassigned:           m.Unassigned,
	}, nil
}

func (c *DTrackClient) UploadSBOM(ctx context.Context, projectUUID string, sbomContent []byte, autoCreate bool) error {
	url := fmt.Sprintf("%s/api/v1/bom", c.baseURL)

	body := map[string]any{
		"project":    projectUUID,
		"autoCreate": autoCreate,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upload sbom: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dtrack API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

func (c *DTrackClient) get(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dtrack API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dtrack API error (status %d): %s", resp.StatusCode, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

func mapDTrackSeverity(sev string) models.Severity {
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
