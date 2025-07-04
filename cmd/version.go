package cmd

import (
	_ "embed"
	"fmt"
	"github.com/spf13/cobra"
)

//go:embed version.txt
var version string

var versionCmd = &cobra.Command{
	Use:     "version",
	Short:   "Print jmk48over version",
	Aliases: []string{"v"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("jmk48over version: %s\n", version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
