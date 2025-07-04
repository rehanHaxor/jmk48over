package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// runCmd hanyalah alias untuk perintah 'gas', jadi kita arahkan ke sana.
var runCmd = &cobra.Command{
	Use:     "run",
	Short:   "Alias untuk 'gas' (scan subdomain takeover)",
	Aliases: []string{"r"},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("📢 Command 'run' sudah digantikan oleh 'gas'. Gunakan:")
		fmt.Println("    jmk48over gas --targets subdomains.txt --output hasil.json")
	},
}

func init() {
	rootCmd.AddCommand(runCmd)
}
