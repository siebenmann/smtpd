//
// Let's see if I can write Go tests

package smtpd

import "testing"

// This should contain only things that are actually valid. Do not test
// error handling here.
var smtpValidTests = []struct {
	line string   // Input line
	cmd  SmtpCmds // Output SmtpCmd
	arg  string   // Output argument
}{
	{"HELO localhost", HELO, "localhost"},
	{"HELO", HELO, ""},
	{"EHLO fred", EHLO, "fred"},
	{"EHLO", EHLO, ""},
	{"MAIL FROM:<>", MAILFROM, ""},
	{"MAIL FROM:<fred@example.com>", MAILFROM, "fred@example.com"},
	{"RCPT TO:<fred@example.com>", RCPTTO, "fred@example.com"},
	{"DATA", DATA, ""},
	{"QUIT", QUIT, ""},
	{"RSET", RSET, ""},
	{"NOOP", NOOP, ""},
	{"VRFY fred@example.org", VRFY, "fred@example.org"},
	{"EXPN fred@example.net", EXPN, "fred@example.net"},
	{"HELP barney", HELP, "barney"},
	{"HELP", HELP, ""},

	// Torture cases.
	{"RCPT TO:<a>", RCPTTO, "a"}, // Minimal address
	{"HELO    ", HELO, ""},       // all blank optional argument
	{"HELO   a    ", HELO, "a"},  // whitespace in argument

	// Accepted as valid by ParseCmd even if they're wrong by the views
	// of higher layers.
	{"RCPT TO:<>", RCPTTO, ""},
	{"MAIL FROM:<<>>", MAILFROM, "<>"},
	{"MAIL FROM:<barney>", MAILFROM, "barney"},

	// Extended MAIL FROM and RCPT TO with additional arguments.
	{"MAIL FROM:<fred@example.mil> SIZE=10000", MAILFROM, "fred@example.mil"},
	{"RCPT TO:<fred@example.mil> SIZE=100", RCPTTO, "fred@example.mil"},

	// commands in lower case and mixed case, preserving argument case
	{"mail from:<FreD@Barney>", MAILFROM, "FreD@Barney"},
	{"Rcpt To:<joe@joe>", RCPTTO, "joe@joe"},
}

func TestGoodParses(t *testing.T) {
	var s SmtpCmd
	for _, src := range smtpValidTests {
		s = ParseCmd(src.line)
		if s.cmd != src.cmd {
			t.Fatalf("mismatched CMD result on '%s': got %v wanted %v", src.line, s.cmd, src.cmd)
		}
		if len(s.err) > 0 {
			t.Fatalf("command failed on '%s': error '%s'", src.line, s.err)
		}
		if src.arg != s.arg {
			t.Fatalf("mismatched arg results on '%s': got %v expected %v", src.line, s.arg, src.arg)
		}
	}
}

// We mostly don't match on the exact error text.
var smtpInvalidTests = []struct {
	line string   // Input line
	cmd  SmtpCmds // Output SmtpCmd
	err  string   // Output err to check if non-empty
}{
	{"argble", BadCmd, ""},
	// UTF-8, and I want to test that this is specifically recognized
	// in an otherwise valid command
	{"MAIL FROM:<Å@fred.com>", BadCmd, "command contains non 7-bit ASCII"},

	// prefix validation
	{"VRFYFred", BadCmd, ""},
	{"MAIL FROMFred", BadCmd, ""},

	// malformed or missing addresses
	{"MAIL FROM <fred>", MAILFROM, ""},
	{"RCPT TO: <fred> ", RCPTTO, ""},
	{"MAIL FROM:", MAILFROM, ""},
	{"MAIL FROM:<", MAILFROM, ""},
	{"MAIL FROM:<fred@barney", MAILFROM, ""},

	// no space between > and param
	{"MAIL FROM:<fred@barney>SIZE=100", MAILFROM, ""},

	// No arguments
	{"VRFY", VRFY, ""},
	{"EXPN", EXPN, ""},

	// Extra arguments on commands that don't take them.
	{"RSET fred", RSET, ""},
	{"NOOP fred", NOOP, ""},
	{"DATA fred", DATA, ""},
	{"QUIT fred", QUIT, ""},
}

func TestBadParses(t *testing.T) {
	var s SmtpCmd
	for _, inp := range smtpInvalidTests {
		s = ParseCmd(inp.line)
		if len(s.err) == 0 {
			t.Fatalf("'%s' not detected as error: cmd %v arg '%v'", inp.line, s.cmd, s.arg)
		}
		if inp.cmd != s.cmd {
			t.Fatalf("mismatched CMD on '%s': got %v expected %v", inp.line, s.cmd, inp.cmd)
		}

		if len(inp.err) > 0 && inp.err != s.err {
			t.Fatalf("wrong error string on '%s': got '%s' expected '%s'", inp.line, s.err, inp.err)
		}
	}
}

// This is a very quick test for basic functionality.
func TestParam(t *testing.T) {
	s := ParseCmd("MAIL FROM:<fred@barney.com> SIZE=1000")
	// We assume that basic parsing works and don't check.
	if s.params != "SIZE=1000" {
		t.Fatalf("MAIL FROM params failed: expected 'SIZE=1000', got '%s'", s.params)
	}
	s = ParseCmd("MAIL FROM:<fred@barney.com>")
	if len(s.params) > 0 {
		t.Fatalf("MAIL FROM w/o params got a parms value of: '%s'", s.params)
	}
}
