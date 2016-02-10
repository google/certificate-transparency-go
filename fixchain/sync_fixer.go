package fixchain

import (
	"net/http"

	"github.com/google/certificate-transparency/go/x509"
)

type Fixer struct {
	client *http.Client
}

type ChainToFix struct {
	cert  *x509.Certificate
	chain []*x509.Certificate
	roots *x509.CertPool
}

func (f *Fixer) Fix(chainsToFix []*ChainToFix) ([][]*x509.Certificate, []*FixError) {
	chains := make(chan []*x509.Certificate)
	errors := make(chan *FixError)
	af := NewAsyncFixer(100, chains, errors, f.client, false)

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
		af.QueueChain(ctf.cert, ctf.chain, ctf.roots)
	}

	af.Wait()
	close(chains)
	close(errors)

	chs, ferrs := <-chainList, <-errorList

	return chs, ferrs
}

func NewFixer(client *http.Client) *Fixer {
	f := &Fixer{
		client: client,
	}
	return f
}
