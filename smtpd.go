//
// Package smtpd handles the low level of the server side of the SMTP
// protocol. It does not handle high level details like what addresses
// should be accepted or what should happen with email once it has
// been fully received; those decisions are instead delegated to
// whatever is driving smtpd.  Smtpd's purpose is simply to handle the
// grunt work of a reasonably RFC compliant SMTP server, taking care
// of things like proper command sequencing, TLS, and basic
// correctness of some things.
//
// Normal callers should create a new connection with NewConn()
// and then repeatedly call .Next() on it, which will return a
// series of meaningful SMTP events, primarily EHLO/HELO, MAIL
// FROM, RCPT TO, DATA, and then the message data if things get
// that far.
//
// The Conn framework puts timeouts on input and output and size
// limits on input messages (and input lines, but that's much larger
// than the RFC requires so it shouldn't matter). See DefaultLimits
// and SetLimits().
//
// TODO: set the server software name somehow, for the greeting banner?
// More control over the greeting banner?
//
package smtpd

// See http://en.wikipedia.org/wiki/Extended_SMTP#Extensions

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

// The time format we log messages in.
const TimeFmt = "2006-01-02 15:04:05 -0700"

// Command represents known SMTP commands in encoded form.
type Command int

// Recognized SMTP commands. Not all of them do anything
// (eg AUTH, VRFY, and EXPN are just refused).
const (
	noCmd  Command = iota // artificial zero value
	BadCmd Command = iota
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

// ParsedLine represents a parsed SMTP command line.  Err is set if
// there was an error, empty otherwise. Cmd may be BadCmd or a
// command, even if there was an error.
type ParsedLine struct {
	Cmd    Command
	Arg    string
	Params string // present only on ESMTP MAIL FROM and RCPT TO.
	Err    string
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

// ParseCmd parses a SMTP command line and returns the result.
// The line should have the ending CR-NL already removed.
func ParseCmd(line string) ParsedLine {
	var res ParsedLine
	res.Cmd = BadCmd

	// We're going to upper-case this, which may explode on us if this
	// is UTF-8 or anything that smells like it.
	if !isall7bit([]byte(line)) {
		res.Err = "command contains non 7-bit ASCII"
		return res
	}

	// Search in the command table for the prefix that matches. If
	// it's not found, this is definitely not a good command.
	// We search on an upper-case version of the line to make my life
	// much easier.
	found := -1
	upper := strings.ToUpper(line)
	for i := range smtpCommand {
		if strings.HasPrefix(upper, smtpCommand[i].text) {
			found = i
			break
		}
	}
	if found == -1 {
		res.Err = "unrecognized command"
		return res
	}

	// Validate that we've ended at a word boundary, either a space or
	// ':'. If we don't, this is not a valid match. Note that we now
	// work with the original-case line, not the upper-case version.
	cmd := smtpCommand[found]
	llen := len(line)
	clen := len(cmd.text)
	if !(llen == clen || line[clen] == ' ' || line[clen] == ':') {
		res.Err = "unrecognized command"
		return res
	}

	// This is a real command, so we must now perform real argument
	// extraction and validation. At this point any remaining errors
	// are command argument errors, so we set the command type in our
	// result.
	res.Cmd = cmd.cmd
	switch cmd.argtype {
	case noArg:
		if llen != clen {
			res.Err = "SMTP command does not take an argument"
			return res
		}
	case mustArg:
		if llen <= clen+1 {
			res.Err = "SMTP command requires an argument"
			return res
		}
		// Even if there are nominal characters they could be
		// all whitespace.
		t := strings.TrimSpace(line[clen+1:])
		if len(t) == 0 {
			res.Err = "SMTP command requires an argument"
			return res
		}
		res.Arg = t
	case canArg:
		if llen > clen+1 {
			res.Arg = strings.TrimSpace(line[clen+1:])
		}
	case colonAddress:
		var idx int
		// Minimum llen is clen + ':<>', three characters
		if llen < clen+3 {
			res.Err = "SMTP command requires an address"
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
				res.Err = "improper argument formatting"
				return res
			}
		}
		// NOTE: the RFC is explicit that eg 'MAIL FROM: <addr...>'
		// is not valid, ie there cannot be a space between the : and
		// the '<'. Normally we'd refuse to accept it, but a few too
		// many things invalidly generate it.
		if line[clen] != ':' || idx == -1 {
			res.Err = "improper argument formatting"
			return res
		}
		spos := clen + 1
		if line[spos] == ' ' {
			spos++
		}
		if line[spos] != '<' {
			res.Err = "improper argument formatting"
			return res
		}
		res.Arg = line[spos+1 : idx]
		// As a side effect of this we generously allow trailing
		// whitespace after RCPT TO and MAIL FROM. You're welcome.
		res.Params = strings.TrimSpace(line[idx+1 : llen])
	}
	return res
}

//
// ---
// Protocol state machine

// States of the SMTP conversation. These are bits and can be masked
// together.
type conState int

const (
	sStartup conState = iota // Must be zero value
	sInitial conState = 1 << iota
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
	validin, next conState
}{
	HELO:     {sInitial | sHelo, sHelo},
	EHLO:     {sInitial | sHelo, sHelo},
	MAILFROM: {sHelo, sMail},
	RCPTTO:   {sMail | sRcpt, sRcpt},
	DATA:     {sRcpt, sData},
}

// Limits has the time and message limits for a Conn, as well as some
// additional options.
type Limits struct {
	CmdInput time.Duration // client commands, eg MAIL FROM
	MsgInput time.Duration // total time to get the email message itself
	ReplyOut time.Duration // server replies to client commands
	TLSSetup time.Duration // time limit to finish STARTTLS TLS setup
	MsgSize  int64         // total size of an email message
	BadCmds  int           // how many unknown commands before abort
	NoParams bool          // reject MAIL FROM/RCPT TO with parameters
}

// The default limits that are applied if you do not specify anything.
// Two minutes for command input and command replies, ten minutes for
// receiving messages, and 5 Mbytes of message size.
//
// Note that these limits are not necessarily RFC compliant, although
// they should be enough for real email clients.
var DefaultLimits = Limits{
	CmdInput: 2 * time.Minute,
	MsgInput: 10 * time.Minute,
	ReplyOut: 2 * time.Minute,
	TLSSetup: 4 * time.Minute,
	MsgSize:  5 * 1024 * 1024,
	BadCmds:  5,
	NoParams: true,
}

// Conn represents an ongoing SMTP connection. The TLS fields are
// read-only; the SayTime field may be written to (and defaults to
// false).
//
// Note that this structure cannot be created by hand. Call NewConn.
//
// TODO: this structure is a mess. Clean it up somehow.
type Conn struct {
	conn   net.Conn
	lr     *io.LimitedReader // wraps conn as a reader
	rdr    *textproto.Reader // wraps lr
	logger io.Writer

	state   conState
	badcmds int // count of bad commands so far
	limits  Limits
	delay   time.Duration // see SetDelay()

	// used for state tracking for Accept()/Reject()/Tempfail().
	curcmd  Command
	replied bool
	nstate  conState // next state if command is accepted.

	tlsc      *tls.Config
	TLSOn     bool   // TLS is on in this connection
	TLSCipher uint16 // Negociated TLS cipher. See net/tls.

	SayTime bool   // put the time and date in the server banner
	local   string // Local hostname for server banner
}

// An Event is the sort of event that is returned by Conn.Next().
type Event int

// The different types of SMTP events returned by Next()
const (
	_       Event = iota // make uninitialized Event an error.
	COMMAND Event = iota
	GOTDATA
	DONE
	ABORT
	TLSERROR
)

// EventInfo is what Conn.Next() returns to represent events.
// Cmd and Arg come from ParsedLine.
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
	for i := range b {
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
	c.conn.SetWriteDeadline(time.Now().Add(c.limits.ReplyOut + wd))
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

func fmtBytesLeft(max, cur int64) string {
	if cur == 0 {
		return "0 bytes left"
	}
	return fmt.Sprintf("%d bytes read", max-cur)
}

func (c *Conn) readCmd() string {
	// This is much bigger than the RFC requires.
	c.lr.N = 2048
	// Allow two minutes per command.
	c.conn.SetReadDeadline(time.Now().Add(c.limits.CmdInput))
	line, err := c.rdr.ReadLine()
	// abort not just on errors but if the line length is exhausted.
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		line = ""
		c.log("!", "command abort %s err: %v",
			fmtBytesLeft(2048, c.lr.N), err)
	} else {
		c.log("r", line)
	}
	return line
}

func (c *Conn) readData() string {
	c.conn.SetReadDeadline(time.Now().Add(c.limits.MsgInput))
	c.lr.N = c.limits.MsgSize
	b, err := c.rdr.ReadDotBytes()
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		b = nil
		c.log("!", "DATA abort %s err: %v",
			fmtBytesLeft(c.limits.MsgSize, c.lr.N), err)
	} else {
		c.log("r", ". <end of data>")
	}
	return string(b)
}

func (c *Conn) stopme() bool {
	return c.state == sAbort || c.badcmds > c.limits.BadCmds || c.state == sQuit
}

// AddTLS adds support for TLS to the Conn. It should be called before
// Conn.Next() is called for the first time.
func (c *Conn) AddTLS(tlsc *tls.Config) {
	c.TLSOn = false
	c.tlsc = tlsc
}

// AddDelay adds a delay to the (server) output of every character in
// replies.  This annoys some spammers and may cause them to
// disconnect.
func (c *Conn) AddDelay(delay time.Duration) {
	c.delay = delay
}

// SetLimits sets non-default limits and options on a Conn.
func (c *Conn) SetLimits(limits Limits) {
	c.limits = limits
}

// Accept accepts the current SMTP command, ie gives an appropriate
// 2xx reply to the client.
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
		// We do not advertise SIZE because our size limits
		// are different from the size limits that RFC 1870
		// wants us to use. We impose a flat byte limit while
		// RFC 1870 wants us to not count quoted dots.
		// Advertising SIZE would also require us to parse
		// SIZE=... on MAIL FROM in order to 552 any too-large
		// sizes.
		// On the whole: pass. Cannot implement.
		// (In general SIZE is hella annoying if you read the
		// RFC religiously.)
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

// AcceptData accepts a message (ie, a post-DATA blob) with an ID that
// is reported to the client in the 2xx message. It only does anything
// when the Conn needs to reply to a DATA blob.
func (c *Conn) AcceptData(id string) {
	if c.replied || c.curcmd != DATA || c.state != sPostData {
		return
	}
	c.state = c.nstate
	c.reply("250 I've put it in a can called %s", id)
	c.replied = true
}

// RejectData rejects a message with an ID that is reported to the client
// in the 5xx message.
func (c *Conn) RejectData(id string) {
	if c.replied || c.curcmd != DATA || c.state != sPostData {
		return
	}
	c.reply("554 Not put in a can called %s", id)
	c.replied = true
}

// Reject rejects the curent SMTP command, ie gives the client an
// appropriate 5xx message.
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

// Tempfail temporarily rejects the current SMTP command, ie it gives
// the client an appropriate 4xx reply. Properly implemented clients
// will retry temporary failures later.
func (c *Conn) Tempfail() {
	switch c.curcmd {
	case HELO, EHLO:
		c.reply("421 Not available now")
	case MAILFROM, RCPTTO, DATA:
		c.reply("450 Not available")
	}
	c.replied = true
}

// Next returns the next high-level event from the SMTP connection.
//
// Next() guarantees that the SMTP protocol ordering requirements are
// followed and only returns HELO/EHLO, MAIL FROM, RCPT TO, and DATA
// commands, and the actual message submitted. The caller must reset
// all accumulated information about a message when it sees either
// EHLO/HELO or MAIL FROM.
//
// For commands and GOTDATA, the caller may call Reject() or
// Tempfail() to reject or tempfail the command. Calling Accept() is
// optional; Next() will do it for you implicitly.
// It is invalid to call Next() after it has returned a DONE or ABORT
// event.
//
// Next() does almost no checks on the value of EHLO/HELO, MAIL FROM,
// and RCPT TO. For MAIL FROM and RCPT TO it requires them to
// actually be present, but that's about it. It will accept blank
// EHLO/HELO (ie, no argument at all).  It is up to the caller to do
// more validation and then call Reject() (or Tempfail()) as
// appropriate.  MAIL FROM addresses may be blank (""), indicating the
// null sender ('<>'). RCPT TO addresses cannot be; Next() will fail
// those itself.
//
// TLSERROR is returned if the client tried STARTTLS on a TLS-enabled
// connection but the TLS setup failed for some reason (eg the client
// only supports SSLv2). The caller can use this to, eg, decide not to
// offer TLS to that client in the future.
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
		if c.SayTime {
			c.reply("220 %s go-smtpd %s", c.local,
				time.Now().Format(time.RFC1123Z))
		} else {
			c.reply("220 %s go-smtpd", c.local)
		}
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
		if res.Cmd == BadCmd {
			c.badcmds++
			c.reply("501 Bad: %s", res.Err)
			continue
		}
		// Is this command valid in this state at all?
		// Since we implicitly support PIPELINING, which can
		// result in out of sequence commands when earlier ones
		// fail, we don't count out of sequence commands as bad
		// commands.
		t := states[res.Cmd]
		if t.validin != 0 && (t.validin&c.state) == 0 {
			c.reply("503 Out of sequence command")
			continue
		}
		// Error in command?
		if len(res.Err) > 0 {
			c.reply("553 Garbled command: %s", res.Err)
			continue
		}

		// The command is legitimate. Handle it for real.

		// Handle simple commands that are valid in all states.
		if t.validin == 0 {
			switch res.Cmd {
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
				// Since we're about to start chattering on
				// conn outside of our normal framework, we
				// must reset both read and write timeouts
				// to our TLS setup timeout.
				c.conn.SetDeadline(time.Now().Add(c.limits.TLSSetup))
				tlsConn := tls.Server(c.conn, c.tlsc)
				err := tlsConn.Handshake()
				if err != nil {
					c.log("!", "TLS setup failed: %v", err)
					c.state = sAbort
					evt.What = TLSERROR
					evt.Arg = fmt.Sprintf("%v", err)
					return evt
				}
				// With TLS set up, we now want no read and
				// write deadlines on the underlying
				// connection. So cancel all deadlines by
				// providing a zero value.
				c.conn.SetReadDeadline(time.Time{})
				// switch c.conn to tlsConn.
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
		c.curcmd = res.Cmd

		// RCPT TO:<> is invalid; reject it. Otherwise defer all
		// address checking to our callers.
		if res.Cmd == RCPTTO && len(res.Arg) == 0 {
			c.Reject()
			continue
		}
		// reject parameters that we don't accept, which right
		// now is all of them. We reject with the RFC-correct
		// reply instead of a generic one, so we can't use
		// c.Reject().
		if res.Params != "" && c.limits.NoParams {
			c.reply("504 Command parameter not implemented")
			c.replied = true
			continue
		}

		// Real, valid, in sequence command. Deliver it to our
		// caller.
		evt.What = COMMAND
		evt.Cmd = res.Cmd
		// TODO: does this hold down more memory than necessary?
		evt.Arg = res.Arg
		return evt
	}

	// Explicitly mark and notify too many bad commands. This is
	// an out of sequence 'reply', but so what, the client will
	// see it if they send anything more. It will also go in the
	// SMTP command log.
	evt.Arg = ""
	if c.badcmds > c.limits.BadCmds {
		c.reply("554 Too many bad commands")
		c.state = sAbort
		evt.Arg = "too many bad commands"
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

// NewConn creates a new SMTP conversation from conn, the underlying
// network connection involved.  servername is the server name
// displayed in the greeting banner.  A trace of SMTP commands and
// responses (but not email messages) will be written to log if it's
// non-nil.
//
// Log messages start with a character, then a space, then the
// message.  'r' means read from network (client input), 'w' means
// written to the network (server replies), '!'  means an error, and
// '#' is tracking information for the start or the end of the
// connection. Further information is up to whatever is behind 'log'
// to add.
func NewConn(conn net.Conn, servername string, log io.Writer) *Conn {
	c := &Conn{state: sStartup, local: servername, logger: log}
	c.setupConn(conn)
	c.SetLimits(DefaultLimits)
	return c
}
