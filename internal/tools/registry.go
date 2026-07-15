package tools

import (
	"github.com/mark3labs/mcp-go/server"
)

func RegisterAll(s *server.MCPServer) {
	RegisterOSVTools(s)
	RegisterTrivyTools(s)
	RegisterDTrackTools(s)
}
