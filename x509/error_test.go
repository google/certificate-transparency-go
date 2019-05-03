package x509_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/certificate-transparency-go/x509"
)

func TestErrors(t *testing.T) {
	var tests = []struct {
		errs           *x509.Errors
		want           string
		wantVerbose    string
		wantFatal      bool
		wantFirstFatal error
	}{
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{Summary: "Error", Field: "a.b.c"},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					SpecRef:  "RFC5280 s4.1.2.2",
					SpecText: "The serial number MUST be a positive integer",
					Category: x509.MalformedCertificate,
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: Certificate does not comply with MUST clause in spec: RFC5280 s4.1.2.2, 'The serial number MUST be a positive integer')",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					SpecRef:  "RFC5280 s4.1.2.2",
					SpecText: "The serial number MUST be a positive integer",
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: RFC5280 s4.1.2.2, 'The serial number MUST be a positive integer')",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					SpecRef:  "RFC5280 s4.1.2.2",
					Category: x509.MalformedCertificate,
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: Certificate does not comply with MUST clause in spec: RFC5280 s4.1.2.2)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					SpecText: "The serial number MUST be a positive integer",
					Category: x509.MalformedCertificate,
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: Certificate does not comply with MUST clause in spec: 'The serial number MUST be a positive integer')",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary: "Error",
					Field:   "a.b.c",
					SpecRef: "RFC5280 s4.1.2.2",
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: RFC5280 s4.1.2.2)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					SpecText: "The serial number MUST be a positive integer",
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: 'The serial number MUST be a positive integer')",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{
					Summary:  "Error",
					Field:    "a.b.c",
					Category: x509.MalformedCertificate,
				},
			}},
			want:        "Error",
			wantVerbose: "Error (a.b.c: Certificate does not comply with MUST clause in spec)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{Summary: "Error"},
			}},
			want:        "Error",
			wantVerbose: "Error",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{Summary: "Error\nwith newline", Field: "x", Category: x509.InvalidASN1DER},
			}},
			want:        "Error\nwith newline",
			wantVerbose: "Error\nwith newline (x: Invalid ASN.1 distinguished encoding)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{Summary: "Error1", Field: "a.b.c"},
				{Summary: "Error2", Field: "a.b.c.d"},
				{Summary: "Error3", Field: "x.y.z"},
			}},
			want:        "Errors:\n  Error1\n  Error2\n  Error3",
			wantVerbose: "Errors:\n  Error1 (a.b.c)\n  Error2 (a.b.c.d)\n  Error3 (x.y.z)",
		},
		{
			errs: &x509.Errors{Errs: []x509.Error{
				{Summary: "Error1", Field: "a.b.c"},
				{Summary: "Error2", Field: "a.b.c.d", Fatal: true},
				{Summary: "Error3", Field: "x.y.z"},
			}},
			want:        "Errors:\n  Error1\n  Error2\n  Error3",
			wantVerbose: "Errors:\n  Error1 (a.b.c)\n  Error2 (a.b.c.d)\n  Error3 (x.y.z)",
			wantFatal:   true,
		},
	}

	for _, test := range tests {
		if got := test.errs.Error(); got != test.want {
			t.Errorf("Errors(%+v).Error()=%q; want %q", test.errs, got, test.want)
		}
		if got := test.errs.VerboseError(); got != test.wantVerbose {
			t.Errorf("Errors(%+v).VerboseError()=%q; want %q", test.errs, got, test.wantVerbose)
		}
		if got := test.errs.Fatal(); got != test.wantFatal {
			t.Errorf("Errors(%+v).Fatal()=%v; want %v", test.errs, got, test.wantFatal)
		}
	}
}

func TestErrorsRawAppend(t *testing.T) {
	// Pointer receiver can be nil.
	var errs *x509.Errors
	if got, want := errs.Empty(), true; got != want {
		t.Errorf("Errors().Empty()=%t; want %t", got, want)
	}
	// Pointer receiver can point to empty struct.
	errs = &x509.Errors{}
	if got, want := errs.Error(), ""; got != want {
		t.Errorf("Errors().Error()=%q; want %q", got, want)
	}
	if got, want := errs.Empty(), true; got != want {
		t.Errorf("Errors().Empty()=%t; want %t", got, want)
	}
	errs.Errs = append(errs.Errs, x509.Error{
		Summary: "Error",
		Field:   "a.b.c",
		SpecRef: "RFC5280 s4.1.2.2"})
	if got, want := errs.VerboseError(), "Error (a.b.c: RFC5280 s4.1.2.2)"; got != want {
		t.Errorf("Errors(%+v).Error=%q; want %q", errs, got, want)
	}
	if got, want := errs.Empty(), false; got != want {
		t.Errorf("Errors().Empty()=%t; want %t", got, want)
	}
}

func TestErrorsFilter(t *testing.T) {
	var errs x509.Errors
	id := x509.ErrMaxID + 2
	errs.AddID(id, "arg1", 2, "arg3")
	baseErr := errs.Error()

	errs.AddID(x509.ErrMaxID + 1)
	if got, want := errs.Error(), fmt.Sprintf("Errors:\n  %s\n  E%03d: Unknown error ID %v: args []", baseErr, x509.ErrMaxID+1, x509.ErrMaxID+1); got != want {
		t.Errorf("Errors(%+v).Error=%q; want %q", errs, got, want)
	}

	errList := fmt.Sprintf("%d, %d", x509.ErrMaxID+1, x509.ErrMaxID+1)
	filter := x509.ErrorFilter(errList)
	errs2 := errs.Filter(filter)
	if got, want := errs2.Error(), baseErr; got != want {
		t.Errorf("Errors(%+v).Error=%q; want %q", errs, got, want)
	}
}

func TestErrorsAppend(t *testing.T) {
	errA := errors.New("A")
	errB := errors.New("B")
	errC := errors.New("C")
	errD := errors.New("D")
	tests := []struct {
		left, right, want *x509.NonFatalErrors
	}{
		{
			left:  &x509.NonFatalErrors{Errors: []error{errA}},
			right: &x509.NonFatalErrors{Errors: []error{errB}},
			want:  &x509.NonFatalErrors{Errors: []error{errA, errB}},
		},
		{
			left:  &x509.NonFatalErrors{Errors: []error{errA, errB}},
			right: &x509.NonFatalErrors{Errors: []error{errC, errD}},
			want:  &x509.NonFatalErrors{Errors: []error{errA, errB, errC, errD}},
		},
		{
			left:  nil,
			right: &x509.NonFatalErrors{Errors: []error{errC, errD}},
			want:  &x509.NonFatalErrors{Errors: []error{errC, errD}},
		},
		{
			left:  &x509.NonFatalErrors{Errors: []error{errC, errD}},
			right: nil,
			want:  &x509.NonFatalErrors{Errors: []error{errC, errD}},
		},
		{
			left:  nil,
			right: nil,
			want:  nil,
		},
		{
			left:  &x509.NonFatalErrors{Errors: []error{}},
			right: nil,
			want:  &x509.NonFatalErrors{Errors: []error{}},
		},
	}
	for _, test := range tests {
		got := test.left.Append(test.right)
		if !reflect.DeepEqual(got, test.want) {
			t.Errorf("(%+v).Append(%+v)=%v, want %v", test.left, test.right, got, test.want)
		}
	}
}
