package runner

import (
	"context"
	"net"
	"time"
)

// ResolveCNAME mengembalikan semua CNAME dari sebuah subdomain
func ResolveCNAME(domain string) ([]string, error) {
	var result []string

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{
				Timeout: 5 * time.Second,
			}
			// Gunakan Google Public DNS
			return dialer.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cname, err := resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return result, err
	}

	result = append(result, cname)
	return result, nil
}
