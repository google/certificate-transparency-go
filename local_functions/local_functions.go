package localfunctions

import (
	"github.com/golang/glog"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
)

//Returns an in memory copy of a tree stored on a log server
func (src *sourceLog) BuildCurrentTree(ctx context.Context, g *Gossiper) {
	sth, _ := src.Log.GetSTH(ctx)
	originalhash := sth.SHA256RootHash
	glog.Infof("Original hash: %v", originalhash)
	start_index := 0
	end_index := sth.TreeSize
	entries, _ := src.Log.GetEntries(ctx, int64(start_index), int64(end_index))
	glog.Infof("BuildTree: Length of entries = %d", len(entries))
	glog.Info("BuildTree: Building tree locally")
	glog.Info("BuildTree: Initializing tree")
	tree := merkle.NewInMemoryMerkleTree(rfc6962.DefaultHasher)
	glog.Info("BuildTree: Iterating through logentries and adding all chains to tree")
	nodecount := 0
	glog.Infof("BuildTree: Size of tree: %d", end_index)
	glog.Infof("Entries size: %d", len(entries))
	for i := 0; i < int(end_index); i++ {
		e := entries[i]
		//    num_chains:=len(e.Chain) //type []ASN1Cert
		data := e.Chain[1].Data //type []byte
		if len(data) > 0 {
			glog.V(2).Info("BuildTree: Adding leaf")
			tree.AddLeaf(data) //automatically hashes entry and stores in tree
			nodecount++
			levels := tree.LevelCount()
			glog.V(2).Infof("BuildTree: LevelCount=%d", levels)
		}
	}
	root := tree.CurrentRoot()
	hash := root.Hash()
	glog.Infof("BuildTree: Total nodes=%d", nodecount)
	glog.Infof("BuildTree: Current STH: %v", hash)
}

//GenerateTree accepts a size parameter and returns an in memory build of a merkle tree
func GenerateTree(size int) *merkle.InMemoryMerkleTree {
	tree := merkle.NewInMemoryMerkleTree(rfc6962.DefaultHasher)
	glog.Info("GenerateTree: Creating tree of size %d", size)
	leaves := expandLeaves(0, size-1)
	for _, leaf := range leaves {
		tree.AddLeaf([]byte(leaf))
	}
	root := tree.CurrentRoot()
	hash := root.Hash()
	levels := tree.LevelCount()
	glog.Infof("GenerateTree: Total levels=%d", levels)
	glog.Infof("GenerateTree: Current STH: %v", hash)
	return tree
}

//helper function for ConsistencyProof
func expandLeaves(n, m int) []string {
	leaves := make([]string, 0, m-n+1)
	for l := n; l <= m; l++ {
		leaves = append(leaves, fmt.Sprintf("Leaf %d", l))
	}
	return leaves
}

//Returns consistency proof of an in-memory tree
func ConsistencyProof(start int, end int, tree *merkle.InMemoryMerkleTree) []merkle.TreeEntryDescriptor {
	consProof := tree.SnapshotConsistency(int64(start), int64(end))
	glog.Infof("ConsistencyProof: Returned proof of length %d", len(consProof))
	for i := 0; i < len(consProof); i++ {
		entry := consProof[i]
		glog.Infof("ConsistencyProof: node: %v", entry.Value)
	}
	return consProof
}
