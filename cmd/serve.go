package cmd

import (
	"fmt"
	"log"

	dpnserver "github.com/dpndon/dpndon/internal/server"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
)

var (
	transport string
	host      string
	port      int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long:  `Start the dpndon MCP server using the specified transport.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		mcpServer := dpnserver.New(Version)

		switch transport {
		case "stdio":
			log.Printf("dpndon %s starting (stdio)", Version)
			return server.ServeStdio(mcpServer)

		case "sse":
			sseServer := server.NewSSEServer(mcpServer)
			addr := fmt.Sprintf("%s:%d", host, port)
			log.Printf("dpndon %s starting on %s (SSE)", Version, addr)
			return sseServer.Start(addr)

		case "streamable-http":
			httpServer := server.NewStreamableHTTPServer(mcpServer)
			addr := fmt.Sprintf("%s:%d", host, port)
			log.Printf("dpndon %s starting on %s (Streamable HTTP)", Version, addr)
			return httpServer.Start(addr)

		default:
			return fmt.Errorf("unsupported transport: %s (use stdio, sse, or streamable-http)", transport)
		}
	},
}

func init() {
	serveCmd.Flags().StringVarP(&transport, "transport", "t", "stdio", "Transport type: stdio, sse, streamable-http")
	serveCmd.Flags().StringVarP(&host, "host", "H", "localhost", "Host to listen on (for sse/streamable-http)")
	serveCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port to listen on (for sse/streamable-http)")

	rootCmd.AddCommand(serveCmd)
}
