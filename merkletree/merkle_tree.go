package merkletree

/*
#cgo LDFLAGS: -lcrypto
#cgo CPPFLAGS: -I../../cpp
#cgo CXXFLAGS: -std=c++11
#include "merkle_tree_go.h"
*/
import "C"
import (
	"errors"
	"fmt"
)

// CPPMerkleTree provides an interface to the C++ CT MerkleTree library.
// See the go/README file for details on how to build this.
type CPPMerkleTree struct {
	FullMerkleTreeInterface

	// The C++ MerkleTree handle
	peer C.TREE

	// nodeSize contains the size in bytes of the nodes in the MerkleTree
	// referenced by |peer|.
	nodeSize C.size_t
}

// LeafCount is the number of leafs in the tree.
func (m *CPPMerkleTree) LeafCount() uint64 {
	return uint64(C.LeafCount(m.peer))
}

// LevelCount is the number of levels in the tree.
func (m *CPPMerkleTree) LevelCount() uint64 {
	return uint64(C.LevelCount(m.peer))
}

// AddLeaf ads a new leaf to the hash tree. Stores the hash of the leaf data in
// the tree structure, does not store the data itself.
// Returns the position of the leaf in the tree.
func (m *CPPMerkleTree) AddLeaf(leaf []byte) uint64 {
	return uint64(C.AddLeaf(m.peer, C.BYTE_SLICE(&leaf)))
}

// AddLeafHash adds a leaf hash directly to the tree. Returns the position of
// the leaf in the tree.
func (m *CPPMerkleTree) AddLeafHash(hash []byte) uint64 {
	return uint64(C.AddLeafHash(m.peer, C.BYTE_SLICE(&hash)))
}

// LeafHash returns the leaf hash for the leaf at the requested index.
func (m *CPPMerkleTree) LeafHash(leaf uint64) ([]byte, error) {
	hash := make([]byte, m.nodeSize)
	success := C.LeafHash(m.peer, C.BYTE_SLICE(&hash), C.size_t(leaf))
	if !success {
		return nil, fmt.Errorf("failed to get leafhash of leaf %d", leaf)
	}
	return hash, nil
}

// CurrentRoot returns the current root of the tree.
func (m *CPPMerkleTree) CurrentRoot() ([]byte, error) {
	hash := make([]byte, m.nodeSize)
	success := C.CurrentRoot(m.peer, C.BYTE_SLICE(&hash))
	if !success {
		return nil, errors.New("failed to get current root")
	}
	return hash, nil
}

// RootAtSnapshot returns the root at a given index.
func (m *CPPMerkleTree) RootAtSnapshot(snapshot uint64) ([]byte, error) {
	hash := make([]byte, m.nodeSize)
	success := C.RootAtSnapshot(m.peer, C.BYTE_SLICE(&hash), C.size_t(snapshot))
	if !success {
		return nil, fmt.Errorf("failed to get root at snapshot %d", snapshot)
	}
	return hash, nil
}

func splitSlice(slice []byte, chunkSize int) ([][]byte, error) {
	if len(slice)%chunkSize != 0 {
		return nil, fmt.Errorf("slice len %d is not a multiple of chunkSize %d", len(slice), chunkSize)
	}
	numEntries := len(slice) / chunkSize
	ret := make([][]byte, numEntries)
	for i := 0; i < numEntries; i++ {
		start := i * chunkSize
		end := start + chunkSize
		ret[i] = slice[start:end]
	}
	return ret, nil
}

// PathToCurrentRoot returns an audit path to the current root for a given leaf.
func (m *CPPMerkleTree) PathToCurrentRoot(leaf uint64) ([][]byte, error) {
	var numEntries C.size_t
	entryBuffer := make([]byte, C.size_t(m.LevelCount())*m.nodeSize)
	success := C.PathToCurrentRoot(m.peer, C.BYTE_SLICE(&entryBuffer), &numEntries, C.size_t(leaf))
	if !success {
		return nil, fmt.Errorf("failed to get path to current root from leaf %d", leaf)
	}
	return splitSlice(entryBuffer, int(m.nodeSize))
}

// PathToRootAtSnapshot returns an audit path to a given root for a given leaf.
func (m *CPPMerkleTree) PathToRootAtSnapshot(leaf, snapshot uint64) ([][]byte, error) {
	var numEntries C.size_t
	entryBuffer := make([]byte, C.size_t(m.LevelCount())*m.nodeSize)
	success := C.PathToRootAtSnapshot(m.peer, C.BYTE_SLICE(&entryBuffer), &numEntries, C.size_t(leaf), C.size_t(snapshot))
	if !success {
		return nil, fmt.Errorf("failed to get path to root at snapshot %d from leaf %d", snapshot, leaf)
	}
	return splitSlice(entryBuffer, int(m.nodeSize))
}

// SnapshotConsistency returns a consistency proof between two given snapshots.
func (m *CPPMerkleTree) SnapshotConsistency(snapshot1, snapshot2 uint64) ([][]byte, error) {
	var numEntries C.size_t
	entryBuffer := make([]byte, C.size_t(m.LevelCount())*m.nodeSize)
	success := C.SnapshotConsistency(m.peer, C.BYTE_SLICE(&entryBuffer), &numEntries, C.size_t(snapshot1), C.size_t(snapshot2))
	if !success {
		return nil, fmt.Errorf("failed to get path to snapshot consistency from %d to %d", snapshot1, snapshot2)
	}
	return splitSlice(entryBuffer, int(m.nodeSize))
}

// NewCPPMerkleTree returns a new wrapped C++ MerkleTree, using the
// Sha256Hasher.
// It is the caller's responsibility to call DeletePeer() when finished with
// the tree to deallocate its resources.
func NewCPPMerkleTree() *CPPMerkleTree {
	m := &CPPMerkleTree{
		peer: C.NewMerkleTree(C.NewSha256Hasher()),
	}
	m.nodeSize = C.size_t(C.NodeSize(m.peer))
	return m
}

// DeletePeer deallocates the memory used by the C++ MerkleTree peer.
func (m *CPPMerkleTree) DeletePeer() {
	C.DeleteMerkleTree(m.peer)
	m.peer = nil
}
