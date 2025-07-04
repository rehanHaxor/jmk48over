package runner

import (
	"io"
	"log"
	"net/url"
	"regexp"

	"github.com/logrusorgru/aurora"
)

type resultStatus string

const (
	ResultHTTPError     resultStatus = "http error"
	ResultResponseError resultStatus = "response error"
	ResultVulnerable    resultStatus = "vulnerable"
	ResultNotVulnerable resultStatus = "not vulnerable"
)

type Result struct {
	ResStatus    resultStatus
	Status       aurora.Value
	Entry        Fingerprint
	ResponseBody string
	Subdomain    string
	CName        []string
	Service      string
	Vulnerable   bool
}

// checkSubdomain performs HTTP check for the subdomain
func (c *Config) checkSubdomain(subdomain string) Result {
	urlToCheck := subdomain
	if !isValidUrl(urlToCheck) {
		if c.HTTPS {
			urlToCheck = "https://" + subdomain
		} else {
			urlToCheck = "http://" + subdomain
		}
	}

	resp, err := c.client.Get(urlToCheck)
	if err != nil {
		return Result{ResStatus: ResultHTTPError, Status: aurora.Red("HTTP ERROR"), Subdomain: subdomain}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{ResStatus: ResultResponseError, Status: aurora.Red("RESPONSE ERROR"), Subdomain: subdomain}
	}

	body := string(bodyBytes)
	return c.matchResponse(subdomain, body)
}

// matchResponse compares HTTP body with known fingerprints
func (c *Config) matchResponse(subdomain, body string) Result {
	for _, fp := range c.fingerprints {
		if fp.Fingerprint != "" {
			re, err := regexp.Compile(fp.Fingerprint)
			if err != nil {
				log.Printf("Error compiling regex for fingerprint %s: %v", fp.Fingerprint, err)
				continue
			}
			if re.MatchString(body) {
				if fp.Vulnerable {
					return Result{
						ResStatus:    ResultVulnerable,
						Status:       aurora.Green("VULNERABLE"),
						Entry:        fp,
						ResponseBody: body,
						Subdomain:    subdomain,
						CName:        fp.CName,
						Service:      fp.Service,
						Vulnerable:   true,
					}
				} else {
					return Result{
						ResStatus:    ResultNotVulnerable,
						Status:       aurora.Yellow("NOT VULNERABLE"),
						Entry:        fp,
						ResponseBody: body,
						Subdomain:    subdomain,
						CName:        fp.CName,
						Service:      fp.Service,
						Vulnerable:   false,
					}
				}
			}
		}
	}
	return Result{
		ResStatus:    ResultNotVulnerable,
		Status:       aurora.Red("NOT VULNERABLE"),
		Subdomain:    subdomain,
		Vulnerable:   false,
	}
}

// isValidUrl checks if the string is a valid URL
func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	return err == nil
}
