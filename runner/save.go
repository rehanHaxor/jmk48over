package runner

import (
	"encoding/json"
	"fmt"
	"os"
)

// SaveResults menyimpan hasil dalam file JSON dan TXT
func SaveResults(results []ResultScan, base string) error {
	// Save JSON
	jsonFile, err := os.Create(base + ".json")
	if err != nil {
		return err
	}
	defer jsonFile.Close()

	if err := json.NewEncoder(jsonFile).Encode(results); err != nil {
		return err
	}

	// Save TXT
	txtFile, err := os.Create(base + ".txt")
	if err != nil {
		return err
	}
	defer txtFile.Close()

	for _, r := range results {
		status := "SAFE"
		if r.Vulnerable {
			status = "VULNERABLE"
		}
		line := fmt.Sprintf("%s [%s] (%s)\n", r.Subdomain, status, r.Service)
		txtFile.WriteString(line)
	}

	return nil
}
