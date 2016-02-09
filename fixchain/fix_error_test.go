package fixchain

import "testing"

type fixErrorTest struct {
	ferr     FixError
	expected string
}

var fixErrorTests = []fixErrorTest{
	{
		ferr:     FixError{Type: None},
		expected: "None",
	},
	{
		ferr:     FixError{Type: ParseFailure},
		expected: "ParseFailure",
	},
	{
		ferr:     FixError{Type: CannotFetchURL},
		expected: "CannotFetchURL",
	},
	{
		ferr:     FixError{Type: FixFailed},
		expected: "FixFailed",
	},
	{
		ferr:     FixError{Type: LogPostFailed},
		expected: "LogPostFailed",
	},
	{
		ferr:     FixError{Type: VerifyFailed},
		expected: "VerifyFailed",
	},
	{
		ferr:     FixError{},
		expected: "None",
	},
}

func testTypeString(t *testing.T, f *fixErrorTest) {
	str := f.ferr.TypeString()
	if str != f.expected {
		t.Errorf("TypeString() returned incorrect string. "+
			"Expected %s, received %s.", f.expected, str)
	}
}

func TestTypeString(t *testing.T) {
	for _, test := range fixErrorTests {
		testTypeString(t, &test)
	}
}
