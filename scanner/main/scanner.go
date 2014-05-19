package main

import (
	"flag"
	"log"
	"regexp"

	"code.google.com/p/certificate-transparency/src/go/client"
	"code.google.com/p/certificate-transparency/src/go/scanner"
	"code.google.com/p/certificate-transparency/src/go/x509"
)

const (
	// A regex which cannot match any input
	MatchesNothingRegex = "a^"
)

var logUri = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var matchSubjectRegex = flag.String("match_subject_regex", ".*", "Regex to match CN/SAN")
var precertsOnly = flag.Bool("precerts_only", false, "Only match precerts")
var blockSize = flag.Int("block_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var startIndex = flag.Int64("start_index", 0, "Log index to start scanning at")
var quiet = flag.Bool("quiet", false, "Don't print out extra logging messages, only matches.")

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func logCertInfo(index int64, cert *x509.Certificate) {
	log.Printf("Interesting cert at index %d: CN: '%s'", index, cert.Subject.CommonName)
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func logPrecertInfo(index int64, precert *client.Precertificate) {
	log.Printf("Interesting precert at index %d: CN: '%s' Issuer: %s", index,
		precert.TBSCertificate.Subject.CommonName, precert.TBSCertificate.Issuer.CommonName)
}

func main() {
	flag.Parse()
	logClient := client.New(*logUri)
	var certRegex *regexp.Regexp
	precertRegex := regexp.MustCompile(*matchSubjectRegex)
	switch *precertsOnly {
	case true:
		certRegex = regexp.MustCompile(MatchesNothingRegex)
	case false:
		certRegex = precertRegex
	}

	opts := scanner.ScannerOptions{
		Matcher: scanner.MatchSubjectRegex{
			CertificateSubjectRegex:    certRegex,
			PrecertificateSubjectRegex: precertRegex},
		BlockSize:     *blockSize,
		NumWorkers:    *numWorkers,
		ParallelFetch: *parallelFetch,
		StartIndex:    *startIndex,
		Quiet:         *quiet,
	}
	scanner := scanner.NewScanner(logClient, opts)
	scanner.Scan(logCertInfo, logPrecertInfo)
}
