package fixchain

import (
	"crypto/sha256"
	"sync"

	"github.com/google/certificate-transparency/go/x509"
)

// DedupedChain is a chain of certificates with any duplicates dropped
type DedupedChain struct {
	certs []*x509.Certificate
}

// AddCert adds a new certificate to the end of the chain if the cert is not
// already present in the chain
func (d *DedupedChain) AddCert(cert *x509.Certificate) {
	// Check that the certificate isn't being added twice.
	for _, c := range d.certs {
		if c.Equal(cert) {
			return
		}
	}
	d.certs = append(d.certs, cert)
}

const hashSize = sha256.Size

type lockedMap struct {
	m map[[hashSize]byte]bool
	sync.RWMutex
}

func newLockedMap() *lockedMap {
	return &lockedMap{m: make(map[[hashSize]byte]bool)}
}

func (m *lockedMap) get(hash [hashSize]byte) bool {
	m.RLock()
	defer m.RUnlock()
	return m.m[hash]
}

func (m *lockedMap) set(hash [hashSize]byte, b bool) {
	m.Lock()
	defer m.Unlock()
	m.m[hash] = b
}
