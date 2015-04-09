package main

import (
	"compress/zlib"
	"encoding/gob"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"sync"

	"github.com/google/certificate-transparency/go/client"
	"github.com/google/certificate-transparency/go/preload"
	"github.com/google/certificate-transparency/go/scanner"
)

var sourceLogUri = flag.String("source_log_uri", "http://ct.googleapis.com/aviator", "CT log base URI to fetch entries from")
var targetLogUri = flag.String("target_log_uri", "http://example.com/ct", "CT log base URI to add entries to")
var batchSize = flag.Int("batch_size", 1000, "Max number of entries to request at per call to get-entries")
var numWorkers = flag.Int("num_workers", 2, "Number of concurrent matchers")
var parallelFetch = flag.Int("parallel_fetch", 2, "Number of concurrent GetEntries fetches")
var parallelSubmit = flag.Int("parallel_submit", 2, "Number of concurrent add-[pre]-chain requests")
var startIndex = flag.Int64("start_index", 0, "Log index to start scanning at")
var quiet = flag.Bool("quiet", false, "Don't print out extra logging messages, only matches.")
var sctInputFile = flag.String("sct_file", "", "File to save SCTs & leaf data to")

func createMatcher() (scanner.Matcher, error) {
	// Make a "match everything" regex matcher
	precertRegex := regexp.MustCompile(".*")
	certRegex := precertRegex
	return scanner.MatchSubjectRegex{
		CertificateSubjectRegex:    certRegex,
		PrecertificateSubjectRegex: precertRegex}, nil
}

func recordSct(addedCerts chan<- *preload.AddedCert, certDer client.ASN1Cert, sct *client.SignedCertificateTimestamp) {
	addedCert := preload.AddedCert{
		CertDER:                    certDer,
		SignedCertificateTimestamp: *sct,
		AddedOk:                    true,
	}
	addedCerts <- &addedCert
}

func recordFailure(addedCerts chan<- *preload.AddedCert, certDer client.ASN1Cert, addError error) {
	addedCert := preload.AddedCert{
		CertDER:      certDer,
		AddedOk:      false,
		ErrorMessage: addError.Error(),
	}
	addedCerts <- &addedCert
}

func sctWriterJob(addedCerts <-chan *preload.AddedCert, sctWriter io.Writer, wg *sync.WaitGroup) {
	encoder := gob.NewEncoder(sctWriter)

	for c := range addedCerts {
		if encoder != nil {
			err := encoder.Encode(c)
			if err != nil {
				log.Fatalf("failed to encode to %s: %v", *sctInputFile, err)
			}
		}
	}
	wg.Done()
}

func certSubmitterJob(addedCerts chan<- *preload.AddedCert, log_client *client.LogClient, certs <-chan *client.LogEntry,
	wg *sync.WaitGroup) {
	for c := range certs {
		chain := make([]client.ASN1Cert, len(c.Chain))
		chain[0] = c.X509Cert.Raw
		copy(chain[1:], c.Chain)
		sct, err := log_client.AddChain(chain)
		if err != nil {
			log.Printf("failed to add chain with CN %s: %v\n", c.X509Cert.Subject.CommonName, err)
			recordFailure(addedCerts, chain[0], err)
			continue
		}
		recordSct(addedCerts, chain[0], sct)
		if !*quiet {
			log.Printf("Added chain for CN '%s', SCT: %s\n", c.X509Cert.Subject.CommonName, sct)
		}
	}
	wg.Done()
}

func precertSubmitterJob(addedCerts chan<- *preload.AddedCert, log_client *client.LogClient,
	precerts <-chan *client.LogEntry,
	wg *sync.WaitGroup) {
	for c := range precerts {
		chain := make([]client.ASN1Cert, len(c.Chain))
		chain[0] = c.Precert.Raw
		copy(chain[1:], c.Chain)
		sct, err := log_client.AddPreChain(chain)
		if err != nil {
			log.Printf("failed to add pre-chain with CN %s: %v", c.Precert.TBSCertificate.Subject.CommonName, err)
			recordFailure(addedCerts, chain[0], err)
			continue
		}
		recordSct(addedCerts, chain[0], sct)
		if !*quiet {
			log.Printf("Added precert chain for CN '%s', SCT: %s\n", c.Precert.TBSCertificate.Subject.CommonName, sct)
		}
	}
	wg.Done()
}

func main() {
	flag.Parse()
	var sctFileWriter io.Writer
	var err error
	if *sctInputFile != "" {
		sctFileWriter, err = os.Create(*sctInputFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		sctFileWriter = ioutil.Discard
	}

	sctWriter := zlib.NewWriter(sctFileWriter)
	defer func() {
		err := sctWriter.Close()
		if err != nil {
			log.Fatal(err)
		}
	}()

	fetchLogClient := client.New(*sourceLogUri)
	matcher, err := createMatcher()
	if err != nil {
		log.Fatal(err)
	}

	opts := scanner.ScannerOptions{
		Matcher:       matcher,
		BatchSize:     *batchSize,
		NumWorkers:    *numWorkers,
		ParallelFetch: *parallelFetch,
		StartIndex:    *startIndex,
		Quiet:         *quiet,
	}
	scanner := scanner.NewScanner(fetchLogClient, opts)

	certs := make(chan *client.LogEntry, *batchSize**parallelFetch)
	precerts := make(chan *client.LogEntry, *batchSize**parallelFetch)
	addedCerts := make(chan *preload.AddedCert, *batchSize**parallelFetch)

	var sctWriterWG sync.WaitGroup
	go sctWriterJob(addedCerts, sctWriter, &sctWriterWG)

	submitLogClient := client.New(*targetLogUri)

	var submitterWG sync.WaitGroup
	for w := 0; w < *parallelSubmit; w++ {
		submitterWG.Add(2)
		go certSubmitterJob(addedCerts, submitLogClient, certs, &submitterWG)
		go precertSubmitterJob(addedCerts, submitLogClient, precerts, &submitterWG)
	}

	addChainFunc := func(entry *client.LogEntry) {
		certs <- entry
	}
	addPreChainFunc := func(entry *client.LogEntry) {
		precerts <- entry
	}

	scanner.Scan(addChainFunc, addPreChainFunc)

	close(certs)
	close(precerts)
	submitterWG.Wait()
	close(addedCerts)
	sctWriterWG.Wait()
}
