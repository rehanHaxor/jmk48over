package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rehanHaxor/jmk48over/runner"
	"github.com/spf13/cobra"
)

var (
	inputFile   string
	outputFile  string
	doUpdate    bool
	silentMode  bool
	httpCheck   bool
	threads     int
)

var (
	green   = "\033[32m"
	red     = "\033[31m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	reset   = "\033[0m"
)

var rootCmd = &cobra.Command{
	Use:   "jmk48over",
	Short: "🔥 jmk48over - Subdomain Takeover Detection Tool",
	Long: `🚀 jmk48over is a fast and automated subdomain takeover scanner 
inspired by Subzy. Built with 💖 by rehanHaxor.

Examples:
  jmk48over --gas subdomains.txt --output hasil
  jmk48over --gas input.txt --silent --http --output vuln_result`,
	Run: func(cmd *cobra.Command, args []string) {
		start := time.Now()
		PrintBanner()

		// Always check and download fingerprints if not exist
		if _, err := runner.Fingerprints(); err != nil {
			fmt.Println(blue + "[*] Fingerprint file missing or corrupt, downloading..." + reset)
			if err := runner.DownloadFingerprints(); err != nil {
				fmt.Printf(red+"[x] Failed to download fingerprints: %v\n"+reset, err)
				os.Exit(1)
			}
			fmt.Println(green + "[✓] Fingerprints downloaded successfully." + reset)
		}

		if doUpdate {
			fmt.Println(blue + "[*] Checking fingerprint updates..." + reset)
			if err := runner.UpdateFingerprints(); err != nil {
				fmt.Printf(red+"[x] Update failed: %v\n"+reset, err)
				os.Exit(1)
			}
			fmt.Println(green + "[✓] Fingerprints are up to date." + reset)
		}

		if inputFile == "" {
			fmt.Println(red + "[x] Please provide input using --gas <file>" + reset)
			cmd.Help()
			os.Exit(1)
		}

		subdomains, err := parseInputFile(inputFile)
		if err != nil {
			fmt.Printf(red+"[x] Failed to read input file: %v\n"+reset, err)
			os.Exit(1)
		}
		fmt.Printf(green+"[+] Loaded %d subdomains from %s\n"+reset, len(subdomains), inputFile)
    
    results, err := runner.RunScan(subdomains, httpCheck, threads)
		if err != nil {
			fmt.Printf(red+"[x] Scan failed: %v\n"+reset, err)
			os.Exit(1)
		}

		vulnCount := 0
		for _, res := range results {
			msg := fmt.Sprintf("%s → %s", res.Subdomain, strings.Join(res.CName, ","))

			if res.Vulnerable {
				vulnCount++
				if !silentMode {
					fmt.Printf(green+"[ VULNERABLE ] "+reset+"%s\n", msg)
					fmt.Printf(yellow+"[ DISCUSSION ] → %s\n"+reset, res.Service)
					fmt.Println("<-------------------->")
				}
			} else {
				if !silentMode {
					fmt.Printf(red+"[ NOT VULNERABLE ] "+reset+"%s\n", msg)
					fmt.Println("<-------------------->")
				}
			}
		}

		if outputFile != "" {
			basePath := strings.TrimSuffix(outputFile, ".json")
			err := runner.SaveResults(results, basePath)
			if err != nil {
				fmt.Printf(red+"[x] Failed to save output: %v\n"+reset, err)
			} else {
				fmt.Printf(green+"[✓] Results saved to %s.json and %s.txt\n"+reset, basePath, basePath)
			}
		}

		dur := time.Since(start)
		fmt.Printf("\n"+blue+"[✓] Done. %d vulnerable out of %d checked in %s\n"+reset, vulnCount, len(subdomains), dur.Round(time.Second))
	},
}

func Execute() {
	rootCmd.Flags().StringVar(&inputFile, "gas", "", "🔥 Input file to scan (list of subdomains)")
	rootCmd.Flags().StringVar(&outputFile, "output", "", "💾 Save results to file (no extension)")
	rootCmd.Flags().BoolVar(&doUpdate, "update", false, "🔁 Update fingerprint database")
	rootCmd.Flags().BoolVar(&silentMode, "silent", false, "🤫 Only show vulnerable subdomains")
	rootCmd.Flags().BoolVar(&httpCheck, "http", false, "🔍 Enable HTTP body fingerprint check for matching signatures")
    rootCmd.Flags().IntVar(&threads, "threads", 20, "⚙️ Number of concurrent threads")

	cobra.CheckErr(rootCmd.Execute())
}

func parseInputFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			subs = append(subs, line)
		}
	}
	return subs, scanner.Err()
}
