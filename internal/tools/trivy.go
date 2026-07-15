package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dpndon/dpndon/internal/scanner"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func RegisterTrivyTools(s *server.MCPServer) {
	fsTool := mcp.NewTool("trivy_scan_fs",
		mcp.WithDescription("Scan a filesystem directory for vulnerabilities, misconfigs, and secrets using Trivy"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to scan"),
		),
		mcp.WithString("severity",
			mcp.Description("Filter by severity: CRITICAL,HIGH,MEDIUM,LOW (comma-separated)"),
		),
		mcp.WithString("scan_types",
			mcp.Description("Scanner types: vuln,misconfig,secret,license (comma-separated, default: vuln)"),
		),
	)
	s.AddTool(fsTool, handleTrivyScanFS)

	imageTool := mcp.NewTool("trivy_scan_image",
		mcp.WithDescription("Scan a container image for vulnerabilities using Trivy"),
		mcp.WithString("image_name",
			mcp.Required(),
			mcp.Description("Container image name and tag (e.g. nginx:latest)"),
		),
		mcp.WithString("severity",
			mcp.Description("Filter by severity: CRITICAL,HIGH,MEDIUM,LOW (comma-separated)"),
		),
	)
	s.AddTool(imageTool, handleTrivyScanImage)

	sbomTool := mcp.NewTool("trivy_scan_sbom",
		mcp.WithDescription("Analyze an SBOM file (CycloneDX/SPDX) for vulnerabilities using Trivy"),
		mcp.WithString("sbom_path",
			mcp.Required(),
			mcp.Description("Path to the SBOM file"),
		),
	)
	s.AddTool(sbomTool, handleTrivyScanSBOM)

	genSBOMTool := mcp.NewTool("trivy_generate_sbom",
		mcp.WithDescription("Generate an SBOM (Software Bill of Materials) from a project directory"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to scan for generating SBOM"),
		),
		mcp.WithString("format",
			mcp.Description("Output format: cyclonedx, spdx, spdx-json (default: cyclonedx)"),
			mcp.Enum("cyclonedx", "spdx", "spdx-json"),
		),
	)
	s.AddTool(genSBOMTool, handleTrivyGenerateSBOM)
}

func handleTrivyScanFS(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	severity, _ := req.GetArguments()["severity"].(string)
	scanTypes, _ := req.GetArguments()["scan_types"].(string)

	s := scanner.NewTrivyScanner("")
	result, err := s.ScanFS(ctx, path, severity, scanTypes)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Trivy scan failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleTrivyScanImage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	imageName, err := req.RequireString("image_name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	severity, _ := req.GetArguments()["severity"].(string)

	s := scanner.NewTrivyScanner("")
	result, err := s.ScanImage(ctx, imageName, severity)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Trivy image scan failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleTrivyScanSBOM(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	sbomPath, err := req.RequireString("sbom_path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	s := scanner.NewTrivyScanner("")
	result, err := s.ScanSBOM(ctx, sbomPath)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Trivy SBOM scan failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleTrivyGenerateSBOM(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	format, _ := req.GetArguments()["format"].(string)

	s := scanner.NewTrivyScanner("")
	data, err := s.GenerateSBOM(ctx, path, format)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Trivy SBOM generation failed: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}
