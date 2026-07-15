package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dpndon/dpndon/internal/scanner"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func RegisterOSVTools(s *server.MCPServer) {
	scanTool := mcp.NewTool("osv_scan_source",
		mcp.WithDescription("Scan a source directory or lockfile for vulnerable dependencies using OSV Scanner"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the directory or lockfile to scan"),
		),
		mcp.WithBoolean("recursive",
			mcp.Description("Recursively scan subdirectories (default: false)"),
		),
	)

	s.AddTool(scanTool, handleOSVScanSource)

	imageTool := mcp.NewTool("osv_scan_image",
		mcp.WithDescription("Scan a container image for vulnerabilities using OSV Scanner"),
		mcp.WithString("image_name",
			mcp.Required(),
			mcp.Description("Container image name and tag (e.g. nginx:latest)"),
		),
	)

	s.AddTool(imageTool, handleOSVScanImage)

	lookupTool := mcp.NewTool("osv_lookup",
		mcp.WithDescription("Look up a specific vulnerability by its ID (e.g. GHSA-xxxx, CVE-xxxx)"),
		mcp.WithString("vuln_id",
			mcp.Required(),
			mcp.Description("Vulnerability ID to look up"),
		),
	)

	s.AddTool(lookupTool, handleOSVLookup)
}

func handleOSVScanSource(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	recursive, _ := req.GetArguments()["recursive"].(bool)

	s := scanner.NewOSVScanner("")
	result, err := s.ScanSource(ctx, path, recursive)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("OSV scan failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleOSVScanImage(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	imageName, err := req.RequireString("image_name")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	s := scanner.NewOSVScanner("")
	result, err := s.ScanImage(ctx, imageName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("OSV image scan failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}

func handleOSVLookup(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	vulnID, err := req.RequireString("vuln_id")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	s := scanner.NewOSVScanner("")
	result, err := s.LookupVulnerability(ctx, vulnID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("OSV lookup failed: %v", err)), nil
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}

	return mcp.NewToolResultText(string(data)), nil
}
