package fixchain

import (
	"net/http"

	"github.com/google/certificate-transparency/go/x509"
)

const workerCount = 100

// Fixer contains methods to synchronously fix certificate chains.
type Fixer struct {
	client *http.Client
}

// ChainToFix contains all the necessary information required to piece together
// a chain that needs constructing or fixing.  Cert is the x509 certificate
// that the chain is for.  Chain is a list of x509 certificates to try as the
// chain for the certificate before attempting to fix the chain if the
// certificates given in Chain are not sufficient.  Roots contains the roots to
// which the chain should lead for the chain to be considered valid.
type ChainToFix struct {
	Cert  *x509.Certificate
	Chain []*x509.Certificate
	Roots *x509.CertPool
}

// Fix synchronously attempts to fix all of the certificate chains passed to it.
// Fix returns a list of successfully constructed or fixed chains, and a list of
// errors that is encountered along the way, each in the form of a FixError.
func (f *Fixer) Fix(chainsToFix []*ChainToFix) ([][]*x509.Certificate, []*FixError) {
	chains := make(chan []*x509.Certificate)
	errors := make(chan *FixError)
	af := NewAsyncFixer(workerCount, chains, errors, f.client, false)

	chainList := make(chan [][]*x509.Certificate)
	defer close(chainList)
	go func() {
		var all [][]*x509.Certificate
		for ch := range chains {
			all = append(all, ch)
		}
		chainList <- all
	}()

	errorList := make(chan []*FixError)
	defer close(errorList)
	go func() {
		var all []*FixError
		for ferr := range errors {
			all = append(all, ferr)
		}
		errorList <- all
	}()

	for _, ctf := range chainsToFix {
		af.QueueChain(ctf.Cert, ctf.Chain, ctf.Roots)
	}

	af.Wait()
	close(chains)
	close(errors)

	chs, ferrs := <-chainList, <-errorList

	return chs, ferrs
}

// NewFixer creates a new synchronous fixer.  client is used to try to get any
// missing certificates that are needed when attempting to fix chains.
func NewFixer(client *http.Client) *Fixer {
	f := &Fixer{
		client: client,
	}
	return f
}
