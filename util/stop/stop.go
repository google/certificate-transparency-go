// Package stop provides mechanism to channel graceful shutdown signal through
// a hierarchy of running components.
package stop

// Stopper allows gracefully stoping multiple operations.
type Stopper chan struct{}

// Stoppable is a subscriber to a Stopper.
type Stoppable <-chan struct{}

// NewStopper creates a new Stopper.
func NewStopper() Stopper {
	return make(chan struct{})
}

// NewStoppable creates a new Stoppable subscribed to this Stopper.
func (s Stopper) NewStoppable() Stoppable {
	return (<-chan struct{})(s)
}

// Stop notifies all subscribed Stoppables that their operation needs to stop.
func (s Stopper) Stop() {
	close(s)
}

// Done returns a channel that closes when it's time to stop.
func (s Stoppable) Done() <-chan struct{} {
	return s
}

// NonStop returns a Stoppable than never gets stopped.
func NonStop() Stoppable {
	return nil // According to Go spec, waitinig on nil channel never terminates.
}
