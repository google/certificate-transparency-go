package stop

import (
	"testing"
	"time"
)

func TestStop(t *testing.T) {
	st := NewStopper()
	sbl := st.NewStoppable()

	time.Sleep(5 * time.Millisecond)
	select {
	case <-sbl.Done():
		t.Error("Stoppable stopped early")
	default:
	}

	st.Stop()
	<-sbl.Done()
}

func TestNonStop(t *testing.T) {
	s := NonStop()
	time.Sleep(5 * time.Millisecond)
	select {
	case <-s.Done():
		t.Error("NonStop stopped")
	default:
	}
}
