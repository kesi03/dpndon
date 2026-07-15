package server

import (
	"github.com/dpndon/dpndon/internal/tools"
	"github.com/mark3labs/mcp-go/server"
)

func New(version string) *server.MCPServer {
	s := server.NewMCPServer(
		"dpndon",
		version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(false, false),
	)

	tools.RegisterAll(s)

	return s
}
