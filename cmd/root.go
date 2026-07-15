package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
)

var rootCmd = &cobra.Command{
	Use:   "dpndon",
	Short: "Dependency security scanner MCP server",
	Long: `dpndon is a Model Context Protocol (MCP) server that wraps multiple
dependency security scanning tools (OSV Scanner, Trivy, Dependency-Track)
behind a unified interface for LLM-powered security analysis.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
