package runner

import (
	"fmt"
	"strings"
)

type ResultScan struct {
	Subdomain  string
	CName      []string
	Service    string
	Discussion string
	Vulnerable bool
}

func RunScan(subdomains []string, httpCheck bool, threads int) ([]ResultScan, error) {
	var results []ResultScan

	fingerprints, err := Fingerprints()
	if err != nil {
		return nil, err
	}

	for _, sub := range subdomains {
		fmt.Printf("[→] Checking: %s\n", sub)

		cnames, err := ResolveCNAME(sub)
		if err != nil || len(cnames) == 0 {
			fmt.Printf("    ↳ \033[31m[ HTTP ERROR ] → %s\033[0m\n", sub)
			fmt.Println("<-------------------->")
			continue
		}

		fmt.Printf("    ↳ CNAME: %s\n", strings.Join(cnames, ", "))

		var matched Fingerprint
		var isVuln bool
		var foundMatch bool

		// CNAME fingerprint matching
		for _, cname := range cnames {
			for _, fp := range fingerprints {
				for _, pattern := range fp.CName {
					if strings.Contains(strings.ToLower(cname), strings.ToLower(pattern)) {
						matched = fp
						isVuln = fp.Vulnerable
						foundMatch = true
						break
					}
				}
				if foundMatch {
					break
				}
			}
			if foundMatch {
				break
			}
		}

		// HTTP body fingerprint matching (optional)
		if httpCheck {
			cfg := Config{HTTPS: true, VerifySSL: false}
			cfg.initHTTPClient()
			cfg.fingerprints = fingerprints
			httpResult := cfg.checkSubdomain(sub)

			if httpResult.ResStatus == ResultVulnerable {
				matched = httpResult.Entry
				isVuln = true
				foundMatch = true
			}
		}

		if foundMatch {
			if isVuln {
				fmt.Printf("    ↳ \033[32m[ VULNERABLE ] -> %s\033[0m\n", sub)
				fmt.Printf("    ↳ \033[33m[ DISCUSSION ] → %s\033[0m\n", matched.Discussion)
			} else {
				fmt.Printf("    ↳ \033[31m[ NOT VULNERABLE ] -> %s\033[0m\n", sub)
			}
		} else {
			fmt.Printf("    ↳ \033[31m[ NOT VULNERABLE ] -> %s\033[0m\n", sub)
		}

		fmt.Println("<-------------------->")

		results = append(results, ResultScan{
			Subdomain:  sub,
			CName:      cnames,
			Service:    matched.Service,
			Discussion: matched.Discussion,
			Vulnerable: isVuln,
		})
	}

	return results, nil
}
