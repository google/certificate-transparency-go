package cache

import "context"

// NonLeafCertificateChainCache is an interface which allows CTFE binaries to use different cache implementations for non-leaf certificate chains.
type NonLeafCertificateChainCache interface {
	// IsLazyLoading returns whether lazy loading is enabled.
	IsLazyLoading() bool

	// Contains returns whether the hash exists in the cache.
	Contains(ctx context.Context, hash string) (bool, error)

	// Get returns the non-leaf certificate chain by the hash.
	Get(ctx context.Context, hash string) ([]byte, error)

	// Set inserts the key-value pair of non-leaf certificate chain.
	Set(ctx context.Context, hash string, chain []byte) error

	// Purge clears all data in the cache.
	Purge(ctx context.Context) error
}
