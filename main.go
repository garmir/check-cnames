package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	concurrency int
	timeout     time.Duration
	verbose     bool
	resolvers   []string
	retries     int
}

var config Config

func init() {
	flag.IntVar(&config.concurrency, "c", 20, "Number of concurrent workers")
	flag.DurationVar(&config.timeout, "t", 5*time.Second, "DNS query timeout")
	flag.BoolVar(&config.verbose, "v", false, "Verbose output (show errors)")
	flag.IntVar(&config.retries, "r", 2, "Number of retries for failed queries")
}

func main() {
	flag.Parse()

	// Default DNS resolvers - using reliable public resolvers
	config.resolvers = []string{
		"1.1.1.1",       // Cloudflare
		"1.0.0.1",       // Cloudflare
		"8.8.8.8",       // Google
		"8.8.4.4",       // Google
		"9.9.9.9",       // Quad9
		"149.112.112.112", // Quad9
		"208.67.222.222", // OpenDNS
		"208.67.220.220", // OpenDNS
	}

	rand.Seed(time.Now().UnixNano())

	type job struct {
		domain string
		server string
	}
	
	jobs := make(chan job, config.concurrency*2)
	results := make(chan string, config.concurrency)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start workers
	for i := 0; i < config.concurrency; i++ {
		wg.Add(1)
		go worker(ctx, jobs, results, &wg)
	}

	// Start result printer
	go func() {
		for result := range results {
			fmt.Println(result)
		}
	}()

	// Read domains from stdin
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		domain := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if domain == "" {
			continue
		}
		
		// Select random resolver for load distribution
		server := config.resolvers[rand.Intn(len(config.resolvers))]
		jobs <- job{domain: domain, server: server}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}

	close(jobs)
	wg.Wait()
	close(results)
}

func worker(ctx context.Context, jobs <-chan job, results chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()

	for j := range jobs {
		processDomain(ctx, j.domain, j.server, results)
	}
}

func processDomain(ctx context.Context, domain, server string, results chan<- string) {
	cname, err := getCNAMEWithRetry(ctx, domain, server)
	if err != nil {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "Error querying %s: %v\n", domain, err)
		}
		return
	}

	// Check if CNAME exists
	if cname == "" {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "No CNAME for %s\n", domain)
		}
		return
	}

	// Check if CNAME resolves
	if !resolves(ctx, cname) {
		results <- fmt.Sprintf("[DANGLING] %s -> %s (does not resolve)", domain, cname)
		
		// Check for potential subdomain takeover services
		service := checkVulnerableService(cname)
		if service != "" {
			results <- fmt.Sprintf("[TAKEOVER] %s -> %s (vulnerable: %s)", domain, cname, service)
		}
	} else if config.verbose {
		results <- fmt.Sprintf("[OK] %s -> %s", domain, cname)
	}
}

func getCNAMEWithRetry(ctx context.Context, domain, server string) (string, error) {
	var lastErr error
	
	for i := 0; i <= config.retries; i++ {
		cname, err := getCNAME(ctx, domain, server)
		if err == nil {
			return cname, nil
		}
		lastErr = err
		
		if i < config.retries {
			time.Sleep(time.Millisecond * 100 * time.Duration(i+1))
		}
	}
	
	return "", lastErr
}

func getCNAME(ctx context.Context, domain, server string) (string, error) {
	c := &dns.Client{
		Timeout: config.timeout,
		Net:     "udp",
	}

	m := &dns.Msg{}
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	m.SetQuestion(domain, dns.TypeCNAME)
	m.RecursionDesired = true

	r, _, err := c.ExchangeContext(ctx, m, server+":53")
	if err != nil {
		return "", fmt.Errorf("DNS query failed: %w", err)
	}

	// First check for CNAME records
	for _, ans := range r.Answer {
		if cname, ok := ans.(*dns.CNAME); ok {
			return strings.TrimSuffix(cname.Target, "."), nil
		}
	}

	// If no CNAME in answer, check if there's an A record (no CNAME)
	for _, ans := range r.Answer {
		if _, ok := ans.(*dns.A); ok {
			return "", nil // Domain has A record, no CNAME
		}
	}

	// Check authority section for SOA (NXDOMAIN or no records)
	if len(r.Ns) > 0 {
		for _, ns := range r.Ns {
			if _, ok := ns.(*dns.SOA); ok {
				return "", nil // No CNAME exists
			}
		}
	}

	return "", nil
}

func resolves(ctx context.Context, domain string) bool {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	
	// Try to resolve with timeout
	resolver := &net.Resolver{
		PreferGo: true,
	}
	
	ctx, cancel := context.WithTimeout(ctx, config.timeout)
	defer cancel()
	
	_, err := resolver.LookupHost(ctx, domain)
	return err == nil
}

func checkVulnerableService(cname string) string {
	cname = strings.ToLower(cname)
	
	// Common subdomain takeover vulnerable services
	vulnerablePatterns := map[string]string{
		".s3.amazonaws.com":           "AWS S3",
		".s3-website":                 "AWS S3",
		".s3.dualstack":              "AWS S3",
		".cloudfront.net":            "AWS CloudFront",
		".elasticbeanstalk.com":      "AWS Elastic Beanstalk",
		".herokuapp.com":             "Heroku",
		".herokudns.com":             "Heroku",
		".wordpress.com":             "WordPress",
		".pantheonsite.io":           "Pantheon",
		".github.io":                 "GitHub Pages",
		".gitlab.io":                 "GitLab Pages",
		".surge.sh":                  "Surge.sh",
		".bitbucket.io":              "Bitbucket",
		".zendesk.com":               "Zendesk",
		".desk.com":                  "Desk.com",
		".fastly.net":                "Fastly",
		".feedpress.me":              "FeedPress",
		".ghost.io":                  "Ghost",
		".helpjuice.com":             "Helpjuice",
		".helpscoutdocs.com":         "HelpScout",
		".azurewebsites.net":         "Azure",
		".cloudapp.azure.com":        "Azure",
		".cloudapp.net":              "Azure",
		".trafficmanager.net":        "Azure Traffic Manager",
		".blob.core.windows.net":     "Azure Blob",
		".azureedge.net":             "Azure CDN",
		".azure-api.net":             "Azure API Management",
		".azurefd.net":               "Azure Front Door",
		".statuspage.io":             "StatusPage",
		".uservoice.com":             "UserVoice",
		".smartling.com":             "Smartling",
		".tictail.com":               "Tictail",
		".campaignmonitor.com":       "Campaign Monitor",
		".createsend.com":            "CreateSend",
		".acquia-sites.com":          "Acquia",
		".proposify.biz":             "Proposify",
		".simplebooklet.com":         "Simplebooklet",
		".getresponse.com":           "GetResponse",
		".vend.com":                  "Vend",
		".jetbrains.space":           "JetBrains Space",
		".myjetbrains.com":           "JetBrains",
		".netlify.app":               "Netlify",
		".netlify.com":               "Netlify",
		".vercel.app":                "Vercel",
		".now.sh":                    "Vercel",
	}

	for pattern, service := range vulnerablePatterns {
		if strings.Contains(cname, pattern) {
			return service
		}
	}

	return ""
}