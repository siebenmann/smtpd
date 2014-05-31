//
//
// See http://en.wikipedia.org/wiki/Extended_SMTP#Extensions
//
package smtpd

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

const TimeFmt = "2006-01-02 15:04:05 -0700"

// An enumeration of SMTP commands that we recognize, plus BadCmd for
// 'no such command'.
type Command int

const (
	noCmd Command = iota // artificial zero value
	BadCmd
	HELO
	EHLO
	MAILFROM
	RCPTTO
	DATA
	QUIT
	RSET
	NOOP
	VRFY
	EXPN
	HELP
	AUTH
	STARTTLS
)

// The result of parsing a SMTP command line to determine the command,
// command argument, optional parameter string for ESTMP MAIL FROM and
// RCPT TO, and an err string if there was an error.
// The err string is set if there was an error, empty otherwise.
type ParsedLine struct {
	cmd    Command
	arg    string
	params string // present only on ESMTP MAIL FROM and RCPT TO.
	err    string
}

// See http://www.ietf.org/rfc/rfc1869.txt for the general discussion of
// params. We do not parse them.

type cmdArgs int

const (
	noArg cmdArgs = iota
	canArg
	mustArg
	colonAddress // for ':<addr>[ options...]'
)

// Our ideal of what requires an argument is slightly relaxed from the
// RFCs, ie we will accept argumentless HELO/EHLO.
var smtpCommand = []struct {
	cmd     Command
	text    string
	argtype cmdArgs
}{
	{HELO, "HELO", canArg},
	{EHLO, "EHLO", canArg},
	{MAILFROM, "MAIL FROM", colonAddress},
	{RCPTTO, "RCPT TO", colonAddress},
	{DATA, "DATA", noArg},
	{QUIT, "QUIT", noArg},
	{RSET, "RSET", noArg},
	{NOOP, "NOOP", noArg},
	{VRFY, "VRFY", mustArg},
	{EXPN, "EXPN", mustArg},
	{HELP, "HELP", canArg},
	{STARTTLS, "STARTTLS", noArg},
	{AUTH, "AUTH", mustArg},
	// TODO: do I need any additional SMTP commands?
}

// Turn a Command int into a string for debugging et al.
func (v Command) String() string {
	switch v {
	case noCmd:
		return "<zero Command value>"
	case BadCmd:
		return "<bad SMTP command>"
	default:
		for _, c := range smtpCommand {
			if c.cmd == v {
				return fmt.Sprintf("<SMTP '%s'>", c.text)
			}
		}
		// ... because someday I may screw this one up.
		return fmt.Sprintf("<Command cmd val %d>", v)
	}
}

// Returns True if the argument is all 7-bit ASCII. This is what all SMTP
// commands are supposed to be, and later things are going to screw up if
// some joker hands us UTF-8 or any other equivalent.
func isall7bit(b []byte) bool {
	for _, c := range b {
		if c > 127 {
			return false
		}
	}
	return true
}

// Parse a SMTP command line and return a ParsedLine structure of the
// result. If there was an error, ParsedLine.err is non-empty.
func ParseCmd(line string) ParsedLine {
	var res ParsedLine
	res.cmd = BadCmd

	// We're going to upper-case this, which may explode on us if this
	// is UTF-8 or anything that smells like it.
	if !isall7bit([]byte(line)) {
		res.err = "command contains non 7-bit ASCII"
		return res
	}

	// Search in the command table for the prefix that matches. If
	// it's not found, this is definitely not a good command.
	// We search on an upper-case version of the line to make my life
	// much easier.
	found := -1
	upper := strings.ToUpper(line)
	for i, _ := range smtpCommand {
		if strings.HasPrefix(upper, smtpCommand[i].text) {
			found = i
			break
		}
	}
	if found == -1 {
		res.err = "unrecognized command"
		return res
	}

	// Validate that we've ended at a word boundary, either a space or
	// ':'. If we don't, this is not a valid match. Note that we now
	// work with the original-case line, not the upper-case version.
	cmd := smtpCommand[found]
	llen := len(line)
	clen := len(cmd.text)
	if !(llen == clen || line[clen] == ' ' || line[clen] == ':') {
		res.err = "unrecognized command"
		return res
	}

	// This is a real command, so we must now perform real argument
	// extraction and validation. At this point any remaining errors
	// are command argument errors, so we set the command type in our
	// result.
	res.cmd = cmd.cmd
	switch cmd.argtype {
	case noArg:
		if llen != clen {
			res.err = "SMTP command does not take an argument"
			return res
		}
	case mustArg:
		if llen <= clen+1 {
			res.err = "SMTP command requires an argument"
			return res
		}
		// Even if there are nominal characters they could be
		// all whitespace.
		t := strings.TrimSpace(line[clen+1:])
		if len(t) == 0 {
			res.err = "SMTP command requires an argument"
			return res
		}
		res.arg = t
	case canArg:
		if llen > clen+1 {
			res.arg = strings.TrimSpace(line[clen+1:])
		}
	case colonAddress:
		var idx int
		// Minimum llen is clen + ':<>', three characters
		if llen < clen+3 {
			res.err = "SMTP command requires an address"
			return res
		}
		// We explicitly check for '>' at the end of the string
		// to accept (at this point) 'MAIL FROM:<<...>>'. This will
		// fail if people also supply ESMTP parameters, of course.
		// Such is life.
		// TODO: reject them here? Maybe it's simpler.
		// BUG: this is imperfect because in theory I think you
		// can embed a quoted '>' inside a valid address and so
		// fool us. But I'm not putting a full RFC whatever address
		// parser in here, thanks, so we'll reject those.
		if line[llen-1] == '>' {
			idx = llen - 1
		} else {
			idx = strings.IndexByte(line, '>')
			if idx != -1 && line[idx+1] != ' ' {
				res.err = "improper argument formatting"
				return res
			}
		}
		if !(line[clen] == ':' && line[clen+1] == '<') || idx == -1 {
			res.err = "improper argument formatting"
			return res
		}
		res.arg = line[clen+2 : idx]
		// As a side effect of this we generously allow trailing
		// whitespace after RCPT TO and MAIL FROM. You're welcome.
		res.params = strings.TrimSpace(line[idx+1 : llen])
	}
	return res
}

//
// ---
// Protocol state machine

// States of the SMTP conversation. These are bits and can be masked
// together.
const (
	sStartup = iota // Must be zero value
	sInitial = 1 << iota
	sHelo
	sMail
	sRcpt
	sData
	sQuit // QUIT received and ack'd, we're exiting.

	// Synthetic state
	sPostData
	sAbort
)

// A command not in the states map is handled in all states (probably to
// be rejected).
var states = map[Command]struct {
	validin, next int
}{
	HELO:     {sInitial | sHelo, sHelo},
	EHLO:     {sInitial | sHelo, sHelo},
	MAILFROM: {sHelo, sMail},
	RCPTTO:   {sMail | sRcpt, sRcpt},
	DATA:     {sRcpt, sData},
}

type Conn struct {
	conn   net.Conn
	lr     *io.LimitedReader
	rdr    *textproto.Reader // this is a wrapped version of lr.
	logger io.Writer

	tlsc      *tls.Config
	TLSOn     bool
	TLSCipher uint16

	delay time.Duration

	state   int
	badcmds int
	local   string // Local hostname for HELO/EHLO

	curcmd  Command
	replied bool
	nstate  int
}

type Event int

const (
	_ Event = iota
	COMMAND
	GOTDATA
	DONE
	ABORT
)

// Returned to higher levels on events.
type EventInfo struct {
	What Event
	Cmd  Command
	Arg  string
}

func (c *Conn) log(dir string, format string, elems ...interface{}) {
	if c.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, elems...)
	c.logger.Write([]byte(fmt.Sprintf("%s %s\n", dir, msg)))
}

// This assumes we're working with a non-Nagle connection. It may not work
// great with TLS, but at least it's at the right level.
func (c *Conn) slowWrite(b []byte) (n int, err error) {
	var x, cnt int
	for i, _ := range b {
		x, err = c.conn.Write(b[i : i+1])
		cnt += x
		if err != nil {
			break
		}
		time.Sleep(c.delay)
	}
	return cnt, err
}

func (c *Conn) reply(format string, elems ...interface{}) {
	var err error
	s := fmt.Sprintf(format, elems...)
	c.log("w", s)
	b := []byte(s + "\r\n")
	// we can ignore the length returned, because Write()'s contract
	// is that it returns a non-nil err if n < len(b).
	// We are cautious about our write deadline.
	wd := c.delay * time.Duration(len(b))
	c.conn.SetWriteDeadline(time.Now().Add(2*time.Minute + wd))
	if c.delay > 0 {
		_, err = c.slowWrite(b)
	} else {
		_, err = c.conn.Write(b)
	}
	if err != nil {
		c.log("!", "reply abort: %v", err)
		c.state = sAbort
	}
}

func (c *Conn) readCmd() string {
	// This is much bigger than the RFC requires.
	c.lr.N = 2048
	// Allow two minutes per command.
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
	line, err := c.rdr.ReadLine()
	// abort not just on errors but if the line length is exhausted.
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		line = ""
		c.log("!", "command abort %d bytes left err: %v", c.lr.N, err)
	} else {
		c.log("r", line)
	}
	return line
}

func (c *Conn) readData() string {
	c.conn.SetReadDeadline(time.Now().Add(10 * time.Minute))
	// TODO: better sizing. 5 Mbytes is relatively absurd, honestly.
	// (but 128Kb caused one abort already)
	c.lr.N = 5 * 1024 * 1024
	b, err := c.rdr.ReadDotBytes()
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		b = nil
		c.log("!", "DATA abort %d bytes left err: %v", c.lr.N, err)
	} else {
		c.log("r", ". <end of data>")
	}
	return string(b)
}

func (c *Conn) stopme() bool {
	return c.state == sAbort || c.badcmds > 5 || c.state == sQuit
}

// TLS must be added before Next() is called for the first time.
func (c *Conn) AddTLS(tlsc *tls.Config) {
	c.TLSOn = false
	c.tlsc = tlsc
}

func (c *Conn) AddDelay(delay time.Duration) {
	c.delay = delay
}

func (c *Conn) Accept() {
	if c.replied {
		return
	}
	oldstate := c.state
	c.state = c.nstate
	switch c.curcmd {
	case HELO:
		c.reply("250 %s Hello %v", c.local, c.conn.RemoteAddr())
	case EHLO:
		c.reply("250-%s Hello %v", c.local, c.conn.RemoteAddr())
		c.reply("250-PIPELINING")
		// STARTTLS RFC says: MUST NOT advertise STARTTLS
		// after TLS is on.
		if c.tlsc != nil && !c.TLSOn {
			c.reply("250-STARTTLS")
		}
		c.reply("250 HELP")
	case MAILFROM, RCPTTO:
		c.reply("250 Okay, I'll believe you for now")
	case DATA:
		// c.curcmd == DATA both when we've received the
		// initial DATA and when we've actually received the
		// data-block. We tell them apart based on the old
		// state, which is sRcpt or sPostData respectively.
		if oldstate == sRcpt {
			c.reply("354 Send away")
		} else {
			c.reply("250 I've put it in a can")
		}
	}
	c.replied = true
}

// Accept a DATA blob with an ID that is reported to the client.
// Only does anything when we need to reply to a DATA blob.
func (c *Conn) AcceptData(id string) {
	if c.replied || c.curcmd != DATA || c.state != sPostData {
		return
	}
	c.state = c.nstate
	c.reply("250 I've put it in a can called %s", id)
	c.replied = true
}
func (c *Conn) RejectData(id string) {
	if c.replied || c.curcmd != DATA || c.state != sPostData {
		return
	}
	c.reply("554 Not put in a can called %s", id)
	c.replied = true
}

func (c *Conn) Reject() {
	switch c.curcmd {
	case HELO, EHLO:
		c.reply("550 Not accepted")
	case MAILFROM, RCPTTO:
		c.reply("550 Bad address")
	case DATA:
		c.reply("554 Not accepted")
	}
	c.replied = true
}
func (c *Conn) Tempfail() {
	switch c.curcmd {
	case HELO, EHLO:
		c.reply("421 Not available now")
	case MAILFROM, RCPTTO, DATA:
		c.reply("450 Not available")
	}
	c.replied = true
}

// Basic syntax checks on the address. We could do more to verify that
// the domain looks sensible but ehh, this is good enough for now.
// Basically we want things that look like 'a@b.c': must have an @,
// must not end with various bad characters, must have a '.' after
// the @.
func addr_valid(a string) bool {
	// caller must reject null address if appropriate.
	if a == "" {
		return true
	}
	lp := len(a) - 1
	if a[lp] == '"' || a[lp] == ']' || a[lp] == '.' {
		return false
	}
	idx := strings.IndexByte(a, '@')
	if idx == -1 || idx == lp {
		return false
	}
	id2 := strings.IndexByte(a[idx+1:], '.')
	if id2 == -1 {
		return false
	}
	return true
}

// Return the next event from the SMTP connection. For commands (and for
// GOTDATA) the caller may call Reject() or Tempfail() to reject or tempfail
// the command. Calling Accept() is optional; Next() will do it for you
// implicitly.
// Only HELO/EHLO, MAIL FROM, RCPT TO, DATA, and the actual message are
// returned. Next() guarantees that the protocol ordering requirements
// are met, so the called must reset all accumulated data when it sees
// a MAIL FROM or HELO/EHLO.
// It is invalid to call Next() after it has returned a DONE or ABORT
// event.
func (c *Conn) Next() EventInfo {
	var evt EventInfo

	if !c.replied && c.curcmd != noCmd {
		c.Accept()
	}
	if c.state == sStartup {
		c.state = sInitial
		// log preceeds the banner in case the banner hits an error.
		c.log("#", "remote %v at %s", c.conn.RemoteAddr(),
			time.Now().Format(TimeFmt))
		c.reply("220 %s go-smtpd", c.local)
	}

	// Read DATA chunk if called for.
	if c.state == sData {
		data := c.readData()
		if len(data) > 0 {
			evt.What = GOTDATA
			evt.Arg = data
			c.replied = false
			// This is technically correct; only a *successful*
			// DATA block ends the mail transaction according to
			// the RFCs. An unsuccessful one must be RSET.
			c.state = sPostData
			c.nstate = sHelo
			return evt
		}
		// If the data read failed, c.state will be sAbort and we
		// will exit in the main loop.
	}

	// Main command loop.
	for {
		if c.stopme() {
			break
		}

		line := c.readCmd()
		if line == "" {
			break
		}

		res := ParseCmd(line)
		if res.cmd == BadCmd {
			c.badcmds += 1
			c.reply("501 Bad: %s", res.err)
			continue
		}
		// Is this command valid in this state at all?
		t := states[res.cmd]
		if t.validin != 0 && (t.validin&c.state) == 0 {
			c.reply("503 Out of sequence command")
			continue
		}
		// Error in command?
		if len(res.err) > 0 {
			c.reply("553 Garbled command: %s", res.err)
			continue
		}

		// The command is legitimate. Handle it for real.

		// Handle simple commands that are valid in all states.
		if t.validin == 0 {
			switch res.cmd {
			case NOOP:
				c.reply("250 Okay")
			case RSET:
				// It's valid to RSET before EHLO and
				// doing so can't skip EHLO.
				if c.state != sInitial {
					c.state = sHelo
				}
				c.reply("250 Okay")
				// RSETs are not delivered to higher levels;
				// they are implicit in sudden MAIL FROMs.
			case QUIT:
				c.state = sQuit
				c.reply("221 Goodbye")
				// Will exit at main loop.
			case HELP:
				c.reply("214 No help here")
			case STARTTLS:
				if c.tlsc == nil || c.TLSOn {
					c.reply("502 Not supported")
					continue
				}
				c.reply("220 Ready to start TLS")
				if c.state == sAbort {
					continue
				}
				tlsConn := tls.Server(c.conn, c.tlsc)
				err := tlsConn.Handshake()
				if err != nil {
					c.log("!", "TLS setup failed: %v", err)
					c.state = sAbort
					continue
				}
				c.setupConn(tlsConn)
				c.TLSOn = true
				cs := tlsConn.ConnectionState()
				c.log("!", "TLS negociated with cipher 0x%04x", cs.CipherSuite)
				c.TLSCipher = cs.CipherSuite
				// By the STARTTLS RFC, we return to our state
				// immediately after the greeting banner
				// and clients must re-EHLO.
				c.state = sInitial
			default:
				c.reply("502 Not supported")
			}
			continue
		}

		// Full state commands
		c.nstate = t.next
		c.replied = false
		c.curcmd = res.cmd
		// Do initial checks on commands.
		switch res.cmd {
		case MAILFROM:
			if !addr_valid(res.arg) {
				c.Reject()
				continue
			}
		case RCPTTO:
			if len(res.arg) == 0 || !addr_valid(res.arg) {
				c.Reject()
				continue
			}
		}

		// Real, valid, in sequence command. Deliver it to our
		// caller.
		evt.What = COMMAND
		evt.Cmd = res.cmd
		// TODO: does this hold down more memory than necessary?
		evt.Arg = res.arg
		return evt
	}

	if c.state == sQuit {
		evt.What = DONE
		c.log("#", "finished at %v", time.Now().Format(TimeFmt))
	} else {
		evt.What = ABORT
		c.log("#", "abort at %v", time.Now().Format(TimeFmt))
	}
	return evt
}

// We need this for re-setting up the connection on TLS start.
func (c *Conn) setupConn(conn net.Conn) {
	c.conn = conn
	// io.LimitReader() returns a Reader, not a LimitedReader, and
	// we want access to the public lr.N field so we can manipulate
	// it.
	c.lr = io.LimitReader(conn, 4096).(*io.LimitedReader)
	c.rdr = textproto.NewReader(bufio.NewReader(c.lr))
}

// Create a new SMTP conversation from conn, the network connection.
// servername is the server name displayed in the greeting banner.
// If non-nil log will receive a trace of SMTP commands and responses
// (but not email messages themselves).
func NewConn(conn net.Conn, servername string, log io.Writer) *Conn {
	c := &Conn{state: sStartup, local: servername, logger: log}
	c.setupConn(conn)
	return c
}
