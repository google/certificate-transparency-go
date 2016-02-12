package fixchain

import (
	"net/http"
	"testing"

	"github.com/google/certificate-transparency/go/x509"
)

var constructChainTests = []fixTest{
	// constructChain()
	{ // Correct chain returns chain
		cert:  googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "constructChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "VeriSign"},
		},
	},
	{ // No roots results in an error
		cert:  googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},

		function:  "constructChain",
		expectErr: true,
	},
	{ // Incomplete chain results in an error
		cert:  googleLeaf,
		roots: []string{verisignRoot},

		function:  "constructChain",
		expectErr: true,
	},
	{ // The wrong intermediate and root results in an error
		cert:  megaLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function:  "constructChain",
		expectErr: true,
	},
	{ // The wrong root results in an error
		cert:  megaLeaf,
		chain: []string{verisignRoot, comodoIntermediate},
		roots: []string{verisignRoot},

		function:  "constructChain",
		expectErr: true,
	},
}

var fixChainTests = []fixTest{
	// fixChain()
	{ // Correct chain returns multiple chains - the complete one initially
		// given, and one containing the cert for Thawte downloaded by
		// augmentIntermediates() from the url in the AIA information of the
		// googleLeaf cert.
		// Note: In practice this should not happen, as fixChain is only called
		// if constructChain fails.
		cert:  googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "fixChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "VeriSign"},
			{"Google", "Thawte", "VeriSign"},
		},
	},
	{ // No roots results in an error
		cert:  googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},

		function:  "fixChain",
		expectErr: true,
	},
	{ // Incomplete chain returns fixed chain
		cert:  googleLeaf,
		roots: []string{verisignRoot},

		function: "fixChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "VeriSign"},
		},
	},
	{ // The wrong intermediate and root results in an error
		cert:  megaLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function:  "fixChain",
		expectErr: true,
	},
	{ // The wrong root results in an error
		cert:  megaLeaf,
		chain: []string{verisignRoot, comodoIntermediate},
		roots: []string{verisignRoot},

		function:  "fixChain",
		expectErr: true,
	},
}

func setUpFix(t *testing.T, i int, ft *fixTest, ch chan *FixError) *toFix {
	// Set up AsyncFixer
	client := &http.Client{}
	cache := &urlCache{cache: make(map[string][]byte), client: client}
	fixer := &AsyncFixer{errors: ch, cache: cache}

	// Create & populate toFix to test from fixTest info
	fix := &toFix{fixer: fixer}
	fix.cert = GetTestCertificateFromPEM(t, ft.cert)

	fix.chain = &dedupedChain{certs: extractTestChain(t, i, ft.chain)}
	fix.roots = extractTestRoots(t, i, ft.roots)

	intermediates := x509.NewCertPool()
	for j, cert := range ft.chain {
		ok := intermediates.AppendCertsFromPEM([]byte(cert))
		if !ok {
			t.Errorf("#%d: Failed to parse intermediate #%d", i, j)
		}
	}

	fix.opts = &x509.VerifyOptions{
		Intermediates:     intermediates,
		Roots:             fix.roots,
		DisableTimeChecks: true,
		KeyUsages:         []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	return fix
}

// Function simply to allow fixer.error chan to be written to if required.
func logErrors(t *testing.T, i int, ch <-chan *FixError) {
	for ferr := range ch {
		t.Logf("#%d: %s", i, ferr.TypeString())
	}
}

func testFix(t *testing.T, i int, ft *fixTest) {
	ch := make(chan *FixError)
	go logErrors(t, i, ch)
	fix := setUpFix(t, i, ft, ch)

	var chains [][]*x509.Certificate
	var ferr *FixError
	switch ft.function {
	case "constructChain":
		chains, ferr = fix.constructChain()
	case "fixChain":
		chains, ferr = fix.fixChain()
	case "handleChain":
		chains, ferr = fix.handleChain()
	}

	if !ft.expectErr && ferr != nil {
		t.Errorf("#%d: Failed to get valid chain: %s", i, ferr.TypeString())
	}

	matchTestChainList(t, i, ft.expectedChains, chains)
}

func TestFix(t *testing.T) {
	var allTests []fixTest
	allTests = append(allTests, constructChainTests...)
	allTests = append(allTests, fixChainTests...)
	allTests = append(allTests, handleChainTests...)
	for i, ft := range allTests {
		testFix(t, i, &ft)
	}
}
