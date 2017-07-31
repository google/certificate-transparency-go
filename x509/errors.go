package x509

import "fmt"

// To preserve error IDs, only append to this list, never insert.
const (
	ErrInvalidID ErrorID = iota

	ErrMaxID
)

// idToError gives a template x509.Error for each defined ErrorID; where the Summary
// field may hold format specifiers that take field parameters.
var idToError = map[ErrorID]Error{}

// NewError builds a new x509.Error based on the template for the given id.
func NewError(id ErrorID, args ...interface{}) Error {
	var err Error
	if id >= ErrMaxID {
		err.ID = id
		err.Summary = fmt.Sprintf("Unknown error ID %v: args %+v", id, args)
		err.Fatal = true
	} else {
		err = idToError[id]
		err.Summary = fmt.Sprintf(err.Summary, args...)
	}
	return err
}
