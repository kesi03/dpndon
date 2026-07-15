package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/mark3labs/mcp-go/server"
	"github.com/dpndon/dpndon/internal/scanner"
	"github.com/mark3labs/mcp-go/mcp"
)

func RegisterDTrackTools(s *server.MCPServer) {
	listProjects := mcp.NewTool("dtrack_list_projects",
		mcp.WithDescription("List projects from Dependency-Track with vulnerability counts"),
		mcp.WithString("query",
			mcp.Description("Search query to filter projects by name"),
		),
		mcp.WithNumber("page",
			mcp.Description("Page number (default: 1)"),
			mcp.DefaultNumber(1),
		),
		mcp.WithNumber("page_size",
			mcp.Description("Results per page (default: 25)"),
			mcp.DefaultNumber(25),
		),
	)
	s.AddTool(listProjects, handleDTrackListProjects)

	listFindings := mcp.NewTool("dtrack_list_findings",
		mcp.WithDescription("Get vulnerability findings for a specific project from Dependency-Track"),
		mcp.WithString("project_uuid",
			mcp.Required(),
			mcp.Description("UUID of the project"),
		),
		mcp.WithString("severity",
			mcp.Description("Filter by severity: CRITICAL,HIGH,MEDIUM,LOW"),
		),
	)
	s.AddTool(listFindings, handleDTrackListFindings)

	searchVuln := mcp.NewTool("dtrack_search_vulnerability",
		mcp.WithDescription("Search for vulnerabilities across the Dependency-Track portfolio"),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Search query (CVE ID, GHSA ID, or keyword)"),
		),
	)
	s.AddTool(searchVuln, handleDTrackSearchVuln)

	portfolioMetrics := mcp.NewTool("dtrack_portfolio_metrics",
		mcp.WithDescription("Get portfolio-wide security metrics from Dependency-Track"),
	)
	s.AddTool(portfolioMetrics, handleDTrackPortfolioMetrics)

	projectMetrics := mcp.NewTool("dtrack_project_metrics",
		mcp.WithDescription("Get security metrics for a specific project from Dependency-Track"),
		mcp.WithString("project_uuid",
			mcp.Required(),
			mcp.Description("UUID of the project"),
		),
	)
	s.AddTool(projectMetrics, handleDTrackProjectMetrics)

	uploadSBOM := mcp.NewTool("dtrack_upload_sbom",
		mcp.WithDescription("Upload a CycloneDX SBOM to Dependency-Track for a project"),
		mcp.WithString("project_uuid",
			mcp.Required(),
			mcp.Description("UUID of the target project"),
		),
		mcp.WithString("sbom_path",
			mcp.Required(),
			mcp.Description("Path to the CycloneDX SBOM file"),
		),
		mcp.WithBoolean("auto_create",
			mcp.Description("Auto-create project if it doesn't exist (default: false)"),
		),
	)
	s.AddTool(uploadSBOM, handleDTrackUploadSBOM)
}

func getDTrackClient() (*scanner.DTrackClient, error) {
	baseURL := os.Getenv("DTRACK_URL")
	apiKey := os.Getenv("DTRACK_API_KEY")

	if baseURL == "" {
		return nil, fmt.Errorf("DTRACK_URL environment variable is not set")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("DTRACK_API_KEY environment variable is not set")
	}

	return scanner.NewDTrackClient(baseURL, apiKey), nil
}

func handleDTrackListProjects(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	query, _ := req.GetArguments()["query"].(string)
	page, _ := req.GetArguments()["page"].(float64)
	pageSize, _ := req.GetArguments()["page_size"].(float64)

	projects, err := client.ListProjects(ctx, query, int(page), int(pageSize))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track API error: %v", err)), nil
	}

	data, err := json.MarshalIndent(projects, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleDTrackListFindings(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	projectUUID, err := req.RequireString("project_uuid")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	severity, _ := req.GetArguments()["severity"].(string)

	findings, err := client.ListFindings(ctx, projectUUID, severity)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track API error: %v", err)), nil
	}

	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleDTrackSearchVuln(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	query, err := req.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	vulns, err := client.SearchVulnerability(ctx, query)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track API error: %v", err)), nil
	}

	data, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleDTrackPortfolioMetrics(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	metrics, err := client.GetPortfolioMetrics(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track API error: %v", err)), nil
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleDTrackProjectMetrics(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	projectUUID, err := req.RequireString("project_uuid")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	metrics, err := client.GetProjectMetrics(ctx, projectUUID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track API error: %v", err)), nil
	}

	data, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleDTrackUploadSBOM(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	client, err := getDTrackClient()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	projectUUID, err := req.RequireString("project_uuid")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	sbomPath, err := req.RequireString("sbom_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	autoCreate, _ := req.GetArguments()["auto_create"].(bool)

	sbomContent, err := os.ReadFile(sbomPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("read SBOM file: %v", err)), nil
	}

	if err := client.UploadSBOM(ctx, projectUUID, sbomContent, autoCreate); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Dependency-Track upload failed: %v", err)), nil
	}

	return mcp.NewToolResultText("SBOM uploaded successfully"), nil
}
