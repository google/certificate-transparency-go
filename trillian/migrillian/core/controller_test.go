package core

import (
	"context"
	"testing"

	ct "github.com/google/certificate-transparency-go"
)

func TestVerifyConsistencyEmptyHead(t *testing.T) {
	controller := new(Controller)
	if controller.verifyConsistency(context.Background(), 0, []byte("abc"), &ct.SignedTreeHead{TreeSize: 100}) != nil {
		t.Errorf("verifyConsistency should always succeed given empty root")
	}
}
