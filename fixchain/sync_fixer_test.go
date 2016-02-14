package fixchain

import (
	"net/http"
	"testing"
)

// Fixer.Fix() tests
func TestSyncFixNone(t *testing.T) {
	f := NewFixer(&http.Client{})
	chains, ferrs := f.Fix(nil)
	if chains != nil {
		t.Errorf("Chains produced")
	}
	if ferrs != nil {
		t.Errorf("Errors produced")
	}
}

func TestSyncFixSingle(t *testing.T) {
	f := NewFixer(&http.Client{})
	for i, test := range handleChainTests {
		chainsToFix := []*ChainToFix{
			&ChainToFix{
				Cert:  GetTestCertificateFromPEM(t, test.cert),
				Chain: extractTestChain(t, i, test.chain),
				Roots: extractTestRoots(t, i, test.roots),
			},
		}
		chains, ferrs := f.Fix(chainsToFix)
		matchTestChainList(t, i, test.expectedChains, chains)
		matchTestErrorList(t, i, test.expectedErrs, ferrs)
	}
}

func TestSyncFixMultiple(t *testing.T) {
	f := NewFixer(&http.Client{})
	var chainsToFix []*ChainToFix
	var expectedChains [][]string
	var expectedErrs []errorType
	for _, test := range handleChainTests {
		chainsToFix = append(chainsToFix, &ChainToFix{
			Cert:  GetTestCertificateFromPEM(t, test.cert),
			Chain: extractTestChain(t, 0, test.chain),
			Roots: extractTestRoots(t, 0, test.roots),
		})
		expectedChains = append(expectedChains, test.expectedChains...)
		expectedErrs = append(expectedErrs, test.expectedErrs...)
	}
	chains, ferrs := f.Fix(chainsToFix)
	matchTestChainList(t, 0, expectedChains, chains)
	matchTestErrorList(t, 0, expectedErrs, ferrs)
}
