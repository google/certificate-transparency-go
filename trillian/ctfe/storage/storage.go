package storage

import (
	"context"
)

// NonLeafCertificateChainStorage is an interface which allows CTFE binaries to use different storage implementations for non-leaf certificate chains.
type NonLeafCertificateChainStorage interface {
	// FindAll returns all key-value pairs of non-leaf certificate chains.
	FindAll(ctx context.Context) (map[string][]byte, error)

	// FindByHash returns the non-leaf certificate chain associated with the provided hash.
	FindByHash(ctx context.Context, hash string) ([]byte, error)

	// Add inserts the key-value pair of non-leaf certificate chain.
	Add(ctx context.Context, hash string, chain []byte) error
}
