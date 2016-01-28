package fixchain

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/certificate-transparency/go/x509"
	"github.com/google/certificate-transparency/go/x509/pkix"
)

type fixTest struct {
	cert string
	chain []string
	roots []string

	function string
	expectedChains [][]string
	expectErr bool
}

var fixTests = []fixTest{
	// constructChain()
	{	// Correct chain returns chain
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "constructChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "Verisign"},
		},
	},
	{	// No roots results in an error
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},

		function: "constructChain",
		expectErr: true,
	},
	{	// No complete chain results in an error
		cert: googleLeaf,
		roots: []string{verisignRoot},

		function: "constructChain",
		expectErr: true,
	},
	{	// The wrong chain results in an error
		cert: smimeLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "constructChain",
		expectErr: true,
	},

	// fixChain()
	{	// Correct chain returns multiple chains - the complete one initially
		// given, and one containing the cert for Thawte downloaded by
		// augmentIntermediates() from the url in the AIA information of the
		// googleLeaf cert.
		// Note: In practice this should not happen, as fixChain is only called
		// if constructChain fails.
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "fixChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "Verisign"},
			{"Google", "Thawte", "Verisign"},
		},
	},
	{	// No roots results in an error
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},

		function: "fixChain",
		expectErr: true,
	},
	{	// Incomplete chain returns fixed chain
		cert: googleLeaf,
		roots: []string{verisignRoot},

		function: "fixChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "Verisign"},
		},
	},

	// handleChain()
	{	// Correct chain returns chain
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "handleChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "Verisign"},
		},
	},
	{	// No roots results in an error
		cert: googleLeaf,
		chain: []string{verisignRoot, thawteIntermediate},

		function: "handleChain",
		expectErr: true,
	},
	{	// Incomplete chain returns a fixed chain
		cert: googleLeaf,
		roots: []string{verisignRoot},

		function: "handleChain",
		expectedChains: [][]string{
			{"Google", "Thawte", "Verisign"},
		},
	},
	{	// The wrong chain results in an error
		cert: smimeLeaf,
		chain: []string{verisignRoot, thawteIntermediate},
		roots: []string{verisignRoot},

		function: "handleChain",
		expectErr: true,
	},
}

func setUpFix(t *testing.T, i int, ft *fixTest) *toFix {
	// Set up Fixer
	client := &http.Client{}
	cache := &urlCache{cache: make(map[string][]byte), client: client}
	fixer := &Fixer{errors: make(chan *FixError), cache: cache}

	// Create & populate toFix to test from fixTest info
	fix := &toFix{fixer:fixer}
	fix.cert = GetTestCertificateFromPEM(t, ft.cert)

	fix.chain = &DedupedChain{}
	for _, cert := range ft.chain {
		fix.chain.AddCert(GetTestCertificateFromPEM(t, cert))
	}

	intermediates := x509.NewCertPool()
	for j, cert := range ft.chain {
		ok := intermediates.AppendCertsFromPEM([]byte(cert))
		if !ok {
			t.Errorf("#%d: Failed to parse intermediate #%d", i, j)
		}
	}

	roots := x509.NewCertPool()
	for j, cert := range ft.roots {
		ok := roots.AppendCertsFromPEM([]byte(cert))
		if !ok {
			t.Errorf("#%d: Failed to parse root #%d", i, j)
		}
	}

	fix.opts = &x509.VerifyOptions{Intermediates: intermediates,
		Roots: roots, DisableTimeChecks: true,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}

	return fix
}

func nameToKey(name *pkix.Name) string {
	return fmt.Sprintf("[%s/%s/%s/%s]", strings.Join(name.Country, ","),
		strings.Join(name.Organization, ","), 
		strings.Join(name.OrganizationalUnit, ","), name.CommonName)
}

func chainToDebugString(chain []*x509.Certificate) string {
	var chainStr string
	for _, cert := range chain {
		if len(chainStr) > 0 {
			chainStr += " -> "
		}
		chainStr += nameToKey(&cert.Subject)
	}
	return chainStr
}

// Function simply to allow fixer.error chan to be written to if required.
func logErrors(t *testing.T, i int, fix *toFix) {
	for ferr := range fix.fixer.errors {
		t.Logf("#%d: %s", i, ferr.TypeString())
	}
}

func testFix(t *testing.T, i int, ft *fixTest) {
	fix := setUpFix(t, i, ft)
	go logErrors(t, i, fix)

	var chains [][]*x509.Certificate
	var ferr *FixError
	switch (ft.function) {
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

	// Check for 1:1 correspondance between expectedChains and the chains that
	// were produced by function call
	if len(ft.expectedChains) != len(chains) {
		t.Errorf("#%d: Wanted %d chains, got back %d", i,
			len(ft.expectedChains), len(chains))
	}

	if ft.expectedChains != nil {
		seen := make([]bool, len(ft.expectedChains))
	NextOutputChain:
		for _, chain := range chains {
		TryNextExpected:
			for j, expChain := range ft.expectedChains {
				if seen[j] {
					continue
				}
				if len(chain) != len(expChain) {
					continue
				}
				for k, cert := range chain {
					if !strings.Contains(nameToKey(&cert.Subject), expChain[k]) {
						continue TryNextExpected
					}
					seen[j] = true
					continue NextOutputChain
				}
			}
			t.Errorf("#%d: No expected chain matched output chain %s", i,
				chainToDebugString(chain))
		}
	}
}

func TestFix(t *testing.T) {
	for i, ft := range fixTests {
		testFix(t, i, &ft)
	}
}
