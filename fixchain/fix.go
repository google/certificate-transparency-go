package fixchain

import (
	"encoding/pem"
	"log"

	"github.com/google/certificate-transparency/go/x509"
)

type toFix struct {
	cert  *x509.Certificate
	chain *DedupedChain
	opts  *x509.VerifyOptions
	fixer *Fixer
}

func (fix *toFix) handleChain() ([][]*x509.Certificate, *FixError) {
	chains, ferr := fix.constructChain()
	if ferr != nil {
		fix.fixer.errors <- ferr
		chains, ferr = fix.fixChain()
	}
	return chains, ferr
}

func (fix *toFix) constructChain() ([][]*x509.Certificate, *FixError) {
	chains, err := fix.cert.Verify(*fix.opts)
	if err != nil {
		fix.fixer.notReconstructed++
		return chains, &FixError{Type: VerifyFailed, Cert: fix.cert,
			Chain: fix.chain.certs, Error: err}
	}
	fix.fixer.reconstructed++
	return chains, nil
}

func (fix *toFix) fixChain() ([][]*x509.Certificate, *FixError) {
	d2 := *fix.chain
	d2.AddCert(fix.cert)
	for _, c := range d2.certs {
		urls := c.IssuingCertificateURL
		for _, url := range urls {
			fix.augmentIntermediates(url)
			chains, err := fix.cert.Verify(*fix.opts)
			if err == nil {
				fix.fixer.fixed++
				return chains, nil
			}
		}
	}
	fix.fixer.notFixed++
	return nil, &FixError{Type: FixFailed, Cert: fix.cert,
		Chain: fix.chain.certs}
}

func (fix *toFix) augmentIntermediates(url string) {
	// PKCS#7 additions as (at time of writing) there is no standard Go PKCS#7
	// implementation
	r := urlReplacement(url)
	if r != nil {
		log.Printf("Replaced %s: %+v", url, r)
		for _, c := range r {
			fix.opts.Intermediates.AddCert(c)
		}
		return
	}

	body, err := fix.fixer.cache.getURL(url)
	if err != nil {
		fix.fixer.errors <- &FixError{Type: CannotFetchURL, Cert: fix.cert,
			Chain: fix.chain.certs, URL: url, Error: err}
		return
	}
	icert, err := x509.ParseCertificate(body)
	if err != nil {
		s, _ := pem.Decode(body)
		if s != nil {
			icert, err = x509.ParseCertificate(s.Bytes)
		}
	}

	if err != nil {
		fix.fixer.errors <- &FixError{Type: ParseFailure, Cert: fix.cert,
			Chain: fix.chain.certs, URL: url, Bad: body, Error: err}
		return
	}
	fix.opts.Intermediates.AddCert(icert)
}
