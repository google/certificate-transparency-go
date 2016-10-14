package main

import (
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	httpclient "github.com/mreiferson/go-httpclient"
)

var logURI = flag.String("log_uri", "http://ct.googleapis.com/aviator", "CT log base URI")
var pubKey = flag.String("pub_key", "", "Name of file containing log's public key")
var certChain = flag.String("cert_chain", "", "Name of file containing certificate chain as concatenated PEM files")

func ctTimestampToTime(ts uint64) time.Time {
	secs := int64(ts / 1000)
	msecs := int64(ts % 1000)
	return time.Unix(secs, msecs*1000000)
}

func signatureToString(signed *ct.DigitallySigned) string {
	return fmt.Sprintf("Signature: Hash=%v Sign=%v Value=%x", signed.HashAlgorithm, signed.SignatureAlgorithm, signed.Signature)
}

func getSTH(logClient *client.LogClient) {
	sth, err := logClient.GetSTH()
	if err != nil {
		log.Fatal(err)
	}
	// Display the STH
	when := ctTimestampToTime(sth.Timestamp)
	fmt.Printf("%v: Got STH for %v log (size=%d) at %v, hash %x\n", when, sth.Version, sth.TreeSize, *logURI, sth.SHA256RootHash)
	fmt.Printf("%v\n", signatureToString(&sth.TreeHeadSignature))
}

func addChain(logClient *client.LogClient) {
	if *certChain == "" {
		log.Fatalf("No certificate chain file specified with -cert_chain")
	}
	rest, err := ioutil.ReadFile(*certChain)
	if err != nil {
		log.Fatalf("Failed to read certificate file: %v", err)
	}
	var chain []ct.ASN1Cert
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			chain = append(chain, ct.ASN1Cert(block.Bytes))
		}
	}

	sct, err := logClient.AddChain(chain)
	if err != nil {
		log.Fatal(err)
	}
	// Display the SCT
	when := ctTimestampToTime(sct.Timestamp)
	fmt.Printf("%v: Uploaded chain of %d certs to %v log at %v\n", when, len(chain), sct.SCTVersion, *logURI)
	fmt.Printf("%v\n", signatureToString(&sct.Signature))
}

func dieWithUsage(msg string) {
	fmt.Fprintf(os.Stderr, msg)
	fmt.Fprintf(os.Stderr, "Usage: ctclient [options] <cmd>\n"+
		"where cmd is one of:\n"+
		"   sth       retrieve signed tree head\n"+
		"   upload    upload cert chain and show SCT (requires -cert_chain)\n")
	os.Exit(1)
}

func main() {
	flag.Parse()
	httpClient := &http.Client{
		Transport: &httpclient.Transport{
			ConnectTimeout:        10 * time.Second,
			RequestTimeout:        30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
		}}
	var logClient *client.LogClient
	if *pubKey == "" {
		logClient = client.New(*logURI, httpClient)
	} else {
		pubkey, err := ioutil.ReadFile(*pubKey)
		if err != nil {
			log.Fatal(err)
		}
		logClient, err = client.NewWithPubKey(*logURI, httpClient, string(pubkey))
		if err != nil {
			log.Fatal(err)
		}
	}
	args := flag.Args()
	if len(args) != 1 {
		dieWithUsage("Need command argument")
	}
	cmd := args[0]
	switch cmd {
	case "sth":
		getSTH(logClient)
	case "upload":
		addChain(logClient)
	default:
		dieWithUsage(fmt.Sprintf("Unknown command '%s'", cmd))
	}
}
