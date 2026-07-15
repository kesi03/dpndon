package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of dpndon",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("dpndon %s\n", Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
