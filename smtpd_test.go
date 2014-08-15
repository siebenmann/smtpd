//
// Let's see if I can write Go tests

package smtpd

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// This should contain only things that are actually valid. Do not test
// error handling here.
var smtpValidTests = []struct {
	line   string  // Input line
	cmd    Command // Output SMTP command
	arg    string  // Output argument
	params string  // Output params
}{
	{"HELO localhost", HELO, "localhost", ""},
	{"HELO", HELO, "", ""},
	{"EHLO fred", EHLO, "fred", ""},
	{"EHLO", EHLO, "", ""},
	{"MAIL FROM:<>", MAILFROM, "", ""},
	{"MAIL FROM:<fred@example.com>", MAILFROM, "fred@example.com", ""},
	{"RCPT TO:<fred@example.com>", RCPTTO, "fred@example.com", ""},
	{"DATA", DATA, "", ""},
	{"QUIT", QUIT, "", ""},
	{"RSET", RSET, "", ""},
	{"NOOP", NOOP, "", ""},
	{"VRFY fred@example.org", VRFY, "fred@example.org", ""},
	{"EXPN fred@example.net", EXPN, "fred@example.net", ""},
	{"HELP barney", HELP, "barney", ""},
	{"HELP", HELP, "", ""},
	{"STARTTLS", STARTTLS, "", ""},
	{"AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=", AUTH, "PLAIN", "dGVzdAB0ZXN0ADEyMzQ="},

	// Torture cases.
	{"RCPT TO:<a>", RCPTTO, "a", ""}, // Minimal address
	{"HELO    ", HELO, "", ""},       // all blank optional argument
	{"HELO   a    ", HELO, "a", ""},  // whitespace in argument
	{"RSET ", RSET, "", ""},          // space after no-arg command

	// Accepted as valid by ParseCmd even if they're wrong by the views
	// of higher layers.
	{"RCPT TO:<>", RCPTTO, "", ""},
	{"MAIL FROM:<<>>", MAILFROM, "<>", ""},
	{"MAIL FROM:<barney>", MAILFROM, "barney", ""},

	// Extended MAIL FROM and RCPT TO with additional arguments.
	{"MAIL FROM:<fred@example.mil> SIZE=10000", MAILFROM, "fred@example.mil", "SIZE=10000"},
	{"RCPT TO:<fred@example.mil> SIZE=100", RCPTTO, "fred@example.mil", "SIZE=100"},

	// commands in lower case and mixed case, preserving argument case
	{"mail from:<FreD@Barney>", MAILFROM, "FreD@Barney", ""},
	{"Rcpt To:<joe@joe>", RCPTTO, "joe@joe", ""},

	// Space after MAIL FROM:
	{"MAIL FROM: <fred@barney>", MAILFROM, "fred@barney", ""},
}

func TestGoodParses(t *testing.T) {
	var s ParsedLine
	for _, inp := range smtpValidTests {
		s = ParseCmd(inp.line)
		if s.Cmd != inp.cmd {
			t.Fatalf("mismatched CMD result on '%s': got %v wanted %v", inp.line, s.Cmd, inp.cmd)
		}
		if len(s.Err) > 0 {
			t.Fatalf("command failed on '%s': error '%s'", inp.line, s.Err)
		}
		if inp.arg != s.Arg {
			t.Fatalf("mismatched arg results on '%s': got %v expected %v", inp.line, s.Arg, inp.arg)
		}
	}
}

// We mostly don't match on the exact error text.
var smtpInvalidTests = []struct {
	line string  // Input line
	cmd  Command // Output SMTP command
	err  string  // Output err to check if non-empty
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
	{"RCPT TO:  <fred> ", RCPTTO, ""},
	{"MAIL FROM:", MAILFROM, ""},
	{"MAIL FROM:<", MAILFROM, ""},
	{"MAIL FROM:<fred@barney", MAILFROM, ""},
	// alleged 'argument' is all white space
	{"MAIL FROM:      ", MAILFROM, ""},

	// no space between > and param
	{"MAIL FROM:<fred@barney>SIZE=100", MAILFROM, ""},

	// No arguments
	{"VRFY", VRFY, ""},
	{"EXPN", EXPN, ""},
	{"AUTH", AUTH, ""},

	// Extra arguments on commands that don't take them.
	{"RSET fred", RSET, ""},
	{"NOOP fred", NOOP, ""},
	{"DATA fred", DATA, ""},
	{"QUIT fred", QUIT, ""},
}

func TestBadParses(t *testing.T) {
	var s ParsedLine
	for _, inp := range smtpInvalidTests {
		s = ParseCmd(inp.line)
		if len(s.Err) == 0 {
			t.Fatalf("'%s' not detected as error: cmd %v arg '%v'", inp.line, s.Cmd, s.Arg)
		}
		if inp.cmd != s.Cmd {
			t.Fatalf("mismatched CMD on '%s': got %v expected %v", inp.line, s.Cmd, inp.cmd)
		}

		if len(inp.err) > 0 && inp.err != s.Err {
			t.Fatalf("wrong error string on '%s': got '%s' expected '%s'", inp.line, s.Err, inp.err)
		}
	}
}

// This is a very quick test for basic functionality.
func TestParam(t *testing.T) {
	s := ParseCmd("MAIL FROM:<fred@barney.com> SIZE=1000")
	// We assume that basic parsing works and don't check.
	if s.Params != "SIZE=1000" {
		t.Fatalf("MAIL FROM params failed: expected 'SIZE=1000', got '%s'", s.Params)
	}
	s = ParseCmd("MAIL FROM:<fred@barney.com>")
	if len(s.Params) > 0 {
		t.Fatalf("MAIL FROM w/o params got a parms value of: '%s'", s.Params)
	}
}

//
// -------
// Current tests are crude because Server() API is not exactly settled.
// We're really testing the sequencing logic, both for accepting a good
// transaction and rejecting out of sequence things.
//
// TODO
// Testing literal text output is a losing approach. What we should do
// is mostly test that the response codes are what we expect. Possibly
// we should connect an instance of the Go SMTP client to the server and
// verify that that works and sees the right EHLO things, once we support
// EHLO things that is.
//

// faker implements the net.Conn() interface.
type faker struct {
	io.ReadWriter
}

func (f faker) Close() error                     { return nil }
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }
func (f faker) RemoteAddr() net.Addr {
	a, _ := net.ResolveTCPAddr("tcp", "127.10.10.100:56789")
	return a
}

// returns expected server output \r\n'd, and the actual output.
// current approach cribbed from the net/smtp tests.
func runSmtpTest(
	serverStr, clientStr string,
	config Config,
	loop func(*Conn),
) (string, string) {
	server := strings.Join(strings.Split(serverStr, "\n"), "\r\n")
	client := strings.Join(strings.Split(clientStr, "\n"), "\r\n")

	var outbuf bytes.Buffer
	writer := bufio.NewWriter(&outbuf)
	reader := bufio.NewReader(strings.NewReader(client))
	cxn := &faker{ReadWriter: bufio.NewReadWriter(reader, writer)}

	// Server(reader, writer)
	conn := NewConn(cxn, config, nil)
	loop(conn)
	writer.Flush()
	return server, outbuf.String()
}

func runSimpleSmtpTest(serverStr, clientStr string) (string, string) {
	return runSmtpTest(serverStr, clientStr, Config{}, func(c *Conn) {
		for {
			evt := c.Next()
			if evt.What == DONE || evt.What == ABORT {
				break
			}
		}
	})
}

func TestBasicSmtpd(t *testing.T) {
	server, actualout := runSimpleSmtpTest(basicServer, basicClient)
	if actualout != server {
		t.Fatalf("Got:\n%s\nExpected:\n%s", actualout, server)
	}
}

// EHLO, send email, send email again, try what should be an out of
// sequence RCPT TO.
var basicClient = `EHLO localhost
MAIL FROM:<a@b.com>
RCPT TO:<c@d.org>
DATA
Subject: A test

Done.
.
MAIL FROM:<a1@b.com>
RCPT TO:<c1@d.org>
DATA
Subject: A test 2

Done. 2.
.
RCPT TO:<e@f.com>
HELO
QUIT
`
var basicServer = `220 localhost go-smtpd
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250 HELP
250 Okay, I'll believe you for now
250 Okay, I'll believe you for now
354 Send away
250 I've put it in a can
250 Okay, I'll believe you for now
250 Okay, I'll believe you for now
354 Send away
250 I've put it in a can
503 Out of sequence command
250 localhost Hello 127.10.10.100:56789
221 Goodbye
`

func TestSequenceErrors(t *testing.T) {
	server, actualout := runSimpleSmtpTest(sequenceServer, sequenceClient)
	if actualout != server {
		t.Fatalf("Got:\n%s\nExpected:\n%s", actualout, server)
	}
}

// A whole series of out of sequence commands, and finally an unrecognized
// one. We try a RSET to validate that it doesn't allow us to MAIL FROM
// without an EHLO.
var sequenceClient = `MAIL FROM:<a@b.com>
RSET
MAIL FROM:<a@b.com>
EHLO localhost
NOOP
RCPT TO:<c@d.com>
MAIL FROM:<a@b.com>
DATA
Subject: yadda yadda
RSET
MAIL FROM:<abc@def.ghi>
RCPT TO:<>
RCPT TO:<abc@def>
RCPT TO:<abc@ghi> SIZE=9999
`
var sequenceServer = `220 localhost go-smtpd
503 Out of sequence command
250 Okay
503 Out of sequence command
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250 HELP
250 Okay
503 Out of sequence command
250 Okay, I'll believe you for now
503 Out of sequence command
501 Bad: unrecognized command
250 Okay
250 Okay, I'll believe you for now
550 Bad address
250 Okay, I'll believe you for now
504 Command parameter not implemented
`

// Test the stream of events emitted from Next(), as opposed to the output
// that the server produces.
var testStream = []struct {
	what Event
	cmd  Command
}{
	{COMMAND, EHLO}, {COMMAND, MAILFROM}, {COMMAND, RCPTTO},
	{COMMAND, RCPTTO}, {COMMAND, DATA}, {GOTDATA, noCmd},
	{COMMAND, MAILFROM}, {COMMAND, MAILFROM}, {DONE, noCmd},
}
var testClient = `EHLO fred
NOOP
RSET
RCPT TO:<barney@jim>
MAIL FROM:<fred@fred>
MAIL FROM:<fred@fred.com>
RCPT TO:<>
RCPT TO:<joe@joe.com>
RCPT TO:<jane@jane.org>
DATA
Subject: A test.

.
RSET
MAIL FROM:<joe@joe.com>
RSET
MAIL FROM:<joe@joe.com>
QUIT
`

func TestSequence(t *testing.T) {
	client := strings.Join(strings.Split(testClient, "\n"), "\r\n")

	var outbuf bytes.Buffer
	writer := bufio.NewWriter(&outbuf)
	reader := bufio.NewReader(strings.NewReader(client))
	cxn := &faker{ReadWriter: bufio.NewReadWriter(reader, writer)}

	// Server(reader, writer)
	var evt EventInfo
	conn := NewConn(cxn, Config{}, nil)
	pos := 0
	for {
		evt = conn.Next()
		ts := testStream[pos]
		if evt.What != ts.what || evt.Cmd != ts.cmd {
			t.Fatalf("Sequence mismatch at step %d: expected %v %v got %v %v\n",
				pos, ts.what, ts.cmd, evt.What, evt.Cmd)
		}
		pos++
		if evt.What == DONE {
			break
		}
	}
}

var authClient1 = `EHLO localhost
MAIL FROM:<a@b.com>
AUTH NOT-ADVERTISED
AUTH TEST initial-auth-resp
*
MAIL FROM:<a@b.com>
QUIT
`
var authServer1 = `220 localhost go-smtpd
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250-AUTH PLAIN LOGIN TEST
250 HELP
530 Authentication required
504 Command parameter not implemented
334 Y2hhbGxlbmdl
501 Authentication aborted
530 Authentication required
221 Goodbye
`

func TestAuthEvents(t *testing.T) {
	cfg := Config{
		Auth: &AuthConfig{Mechanisms: []string{"PLAIN", "LOGIN", "TEST"}},
	}
	server, actualout := runSmtpTest(authServer1, authClient1, cfg, func(c *Conn) {
		var lastevt EventInfo
		for {
			evt := c.Next()
			switch evt.What {
			case DONE:
				return
			case AUTHRESP:
				if evt.Arg != "initial-auth-resp" {
					t.Errorf("event arg mismatch, got %q, want %q", evt.Arg, "initial-auth-resp")
				}
				if !(lastevt.What == COMMAND && lastevt.Cmd == AUTH) {
					t.Error("Next returned out-of-order AUTHRESP, previous event", lastevt)
				}
				c.AuthChallenge([]byte("challenge"))
			case AUTHABORT:
				if lastevt.What != AUTHRESP {
					t.Error("Next returned out-of-order AUTHABORT, previous event", lastevt)
				}
			case COMMAND:
				if evt.Cmd == AUTH {
					if evt.Arg != "TEST" {
						t.Fatalf("event arg mismatch, got %q, want %q", evt.Arg, "TEST")
					}
				} else {
					c.Accept()
				}
			default:
				t.Fatalf("unexpected event: %+v", evt)
			}
			lastevt = evt
		}
	})
	if actualout != server {
		t.Errorf("Server log mismatch, Got:\n%s\nExpected:\n%s", actualout, server)
	}
}

var authClient2 = `EHLO localhost
AUTH TEST
AUTH TEST
QUIT
`
var authServer2 = `220 localhost go-smtpd
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250-AUTH TEST
250 HELP
235 Authentication successful
503 Out of sequence command
221 Goodbye
`

func TestAuthOnce(t *testing.T) {
	cfg := Config{
		Auth: &AuthConfig{Mechanisms: []string{"TEST"}},
	}
	server, actualout := runSmtpTest(authServer2, authClient2, cfg, func(c *Conn) {
		for {
			evt := c.Next()
			if evt.What == DONE || evt.What == ABORT {
				return
			}
			c.Accept()
		}
	})
	if actualout != server {
		t.Errorf("Server log mismatch, Got:\n%s\nExpected:\n%s", actualout, server)
	}
}

var authClient3 = `EHLO localhost
AUTH TEST =
aW5pdGlhbC1yZXNwb25zZQ==
c3Vic2VxdWVudC1yZXNwb25zZQ==
ZmluYWwtcmVzcG9uc2U=
QUIT
`
var authServer3 = `220 localhost go-smtpd
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250-AUTH TEST
250 HELP
334 YzA=
334 ` + `
334 ` + `
235 Authentication successful
221 Goodbye
`

func TestAuthenticateSuccess(t *testing.T) {
	cfg := Config{
		Auth: &AuthConfig{Mechanisms: []string{"TEST"}},
	}
	server, actualout := runSmtpTest(authServer3, authClient3, cfg, func(c *Conn) {
		for {
			switch evt := c.Next(); evt.What {
			case DONE:
				return
			case COMMAND:
				if evt.Cmd == AUTH {
					wantInput := [][]byte{
						{},
						[]byte("initial-response"),
						[]byte("subsequent-response"),
						[]byte("final-response"),
					}
					challenges := [][]byte{
						[]byte("c0"),
						{},
						nil,
					}
					i := 0
					success := c.Authenticate(func(c *Conn, input []byte) {
						if i >= len(wantInput) {
							t.Fatalf("AuthFunc called %d times, expected %d calls", i+1, len(wantInput))
						}
						if !bytes.Equal(input, wantInput[i]) {
							t.Errorf("invalid input: got %q, expected %q", input, wantInput[i])
						}
						if i == len(wantInput)-1 {
							c.Accept()
						} else {
							c.AuthChallenge(challenges[i])
						}
						i++
					})
					if !success {
						t.Errorf("Authenticate returned false, should've returned true to indicate success.")
					}
				} else {
					c.Accept()
				}
			default:
				t.Fatalf("unexpected event: %+v", evt)
			}
		}
	})
	if actualout != server {
		t.Errorf("Server log mismatch, Got:\n%s\nExpected:\n%s", actualout, server)
	}
}

var authClient4 = `EHLO localhost
AUTH TEST initial-resp
AUTH TEST
*
AUTH TEST =
*
QUIT
`
var authServer4 = `220 localhost go-smtpd
250-localhost Hello 127.10.10.100:56789
250-8BITMIME
250-PIPELINING
250-AUTH TEST
250 HELP
501 Invalid authentication response
334 ` + `
501 Authentication aborted
334 ` + `
501 Authentication aborted
221 Goodbye
`

func TestAuthenticateAborts(t *testing.T) {
	cfg := Config{
		Auth: &AuthConfig{Mechanisms: []string{"TEST"}},
	}
	server, actualout := runSmtpTest(authServer4, authClient4, cfg, func(c *Conn) {
		for {
			switch evt := c.Next(); evt.What {
			case DONE:
				return
			case COMMAND:
				if evt.Cmd == AUTH {
					success := c.Authenticate(func(c *Conn, input []byte) {
						if len(input) > 0 {
							t.Errorf("unexpected non-empty AuthFunc input: %q", input)
						}
					})
					if success {
						t.Errorf("Authenticate returned true, should've returned false to indicate abort.")
					}
				} else {
					c.Accept()
				}
			default:
				t.Fatalf("unexpected event: %+v", evt)
			}
		}
	})
	if actualout != server {
		t.Errorf("Server log mismatch, Got:\n%s\nExpected:\n%s", actualout, server)
	}
}
