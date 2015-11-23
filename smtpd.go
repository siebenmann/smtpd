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
// that far. See the .Next documentation for a discussion on how
// to handle AUTH, if this is desired.
//
// The Conn framework puts timeouts on input and output and size
// limits on input messages (and input lines, but that's much larger
// than the RFC requires so it shouldn't matter). See DefaultLimits
// and SetLimits().
//
package smtpd

// See http://en.wikipedia.org/wiki/Extended_SMTP#Extensions

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
	"unicode"
)

// The time format we log messages in.
const TimeFmt = "2006-01-02 15:04:05 -0700"

// Command represents known SMTP commands in encoded form.
type Command int

// Recognized SMTP commands. Not all of them do anything
// (e.g. VRFY and EXPN are just refused).
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
	Cmd Command
	Arg string
	// Params is K=V for ESMTP MAIL FROM and RCPT TO
	// or the initial SASL response for AUTH
	Params string
	Err    string
}

// See http://www.ietf.org/rfc/rfc1869.txt for the general discussion of
// params. We do not parse them.

type cmdArgs int

const (
	noArg cmdArgs = iota
	canArg
	mustArg
	oneOrTwoArgs
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
	{AUTH, "AUTH", oneOrTwoArgs},
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

	// Trim trailing space from the line, because some confused people
	// send eg 'RSET ' or 'QUIT '. Probably other people put trailing
	// spaces on other commands. This is probably not completely okay
	// by the RFCs, but my view is 'real clients trump RFCs'.
	line = strings.TrimRightFunc(line, unicode.IsSpace)

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
		// all whitespace. Although we've trimmed trailing
		// whitespace before now, there could be whitespace
		// *before* the argument and we want to trim it too.
		t := strings.TrimSpace(line[clen+1:])
		if len(t) == 0 {
			res.Err = "SMTP command requires an argument"
			return res
		}
		res.Arg = t
	case oneOrTwoArgs:
		// This implicitly allows 'a b c', with 'b c' becoming
		// the Params value.
		// TODO: is this desirable? Is this allowed by the AUTH RFC?
		parts := strings.SplitN(line, " ", 3)
		switch len(parts) {
		case 1:
			res.Err = "SMTP command requires at least one argument"
		case 2:
			res.Arg = parts[1]
		case 3:
			res.Arg = parts[1]
			res.Params = parts[2]
		}
	case canArg:
		// get rid of whitespace between command and the argument.
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
	sAuth // during SASL dialog
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
	AUTH:     {sHelo, sHelo},
	MAILFROM: {sHelo, sMail},
	RCPTTO:   {sMail | sRcpt, sRcpt},
	DATA:     {sRcpt, sData},
}

// Limits has the time and message limits for a Conn, as well as some
// additional options.
//
// A Conn always accepts 'BODY=[7BIT|8BITMIME]' as the sole MAIL FROM
// parameter, since it advertises support for 8BITMIME.
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

// AuthConfig specifies the authentication mechanisms that
// the server announces as supported.
type AuthConfig struct {
	// Both slices should contain uppercase SASL mechanism names,
	// e.g. PLAIN, LOGIN, EXTERNAL.
	Mechanisms    []string // Supported mechanisms before STARTTLS
	TLSMechanisms []string // Supported mechanisms after STARTTLS
}

// Config represents the configuration for a Conn. If unset, Limits is
// DefaultLimits, LocalName is 'localhost', and SftName is 'go-smtpd'.
type Config struct {
	TLSConfig *tls.Config   // TLS configuration if TLS is to be enabled
	Limits    *Limits       // The limits applied to the connection
	Auth      *AuthConfig   // If non-nil, client must authenticate before MAIL FROM
	Delay     time.Duration // Delay every character in replies by this much.
	SayTime   bool          // report the time and date in the server banner
	LocalName string        // The local hostname to use in messages
	SftName   string        // The software name to use in messages
	Announce  string        // extra stuff to announce in greeting banner
}

// Conn represents an ongoing SMTP connection. The TLS fields are
// read-only.
//
// Note that this structure cannot be created by hand. Call NewConn.
//
// Conn connections always advertise support for PIPELINING and
// 8BITMIME.  STARTTLS is advertised if the Config passed to NewConn()
// has a non-nil TLSConfig. AUTH is advertised if the Config has a
// non-nil Auth.
//
// Conn.Config can be altered to some degree after Conn is created in
// order to manipulate features on the fly. Note that Conn.Config.Limits
// is a pointer and so its fields should not be altered unless you
// know what you're doing and it's your Limits to start with.
type Conn struct {
	conn   net.Conn
	lr     *io.LimitedReader // wraps conn as a reader
	rdr    *textproto.Reader // wraps lr
	logger io.Writer

	Config Config // Connection configuration

	state         conState
	badcmds       int  // count of bad commands so far
	authenticated bool // true after successful auth dialog

	// queued event returned by a forthcoming Next call
	nextEvent *EventInfo

	// used for state tracking for Accept()/Reject()/Tempfail().
	curcmd  Command
	replied bool
	nstate  conState // next state if command is accepted.

	TLSOn    bool                // TLS is on in this connection
	TLSState tls.ConnectionState // TLS connection state
}

// An Event is the sort of event that is returned by Conn.Next().
type Event int

// The different types of SMTP events returned by Next()
const (
	_         Event = iota // make uninitialized Event an error.
	COMMAND   Event = iota
	AUTHRESP        // client sent SASL response
	AUTHABORT       // client aborted SASL dialog by sending '*'
	GOTDATA         // received DATA
	DONE            // client sent QUIT
	ABORT           // input or output error or timeout.
	TLSERROR        // error during TLS setup. Connection is dead.
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
		time.Sleep(c.Config.Delay)
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
	wd := c.Config.Delay * time.Duration(len(b))
	c.conn.SetWriteDeadline(time.Now().Add(c.Config.Limits.ReplyOut + wd))
	if c.Config.Delay > 0 {
		_, err = c.slowWrite(b)
	} else {
		_, err = c.conn.Write(b)
	}
	if err != nil {
		c.log("!", "reply abort: %v", err)
		c.state = sAbort
	}
}

// This is a crude hack for EHLO writing. It skips emitting the reply
// line if we've already aborted (which is assumed to be because of a
// write error). Some clients close the connection as we're writing
// our multi-line EHLO reply out, which otherwise produces one error
// per EHLO line instead of stopping immediately.
//
// This is kind of a code smell in that we're doing the EHLO reply
// in the wrong way, but doing it the current way is also the easiest
// and simplest way. Such is life.
func (c *Conn) replyMore(format string, elems ...interface{}) {
	if c.state != sAbort {
		c.reply(format, elems...)
	}
}

func (c *Conn) replyMulti(code int, format string, elems ...interface{}) {
	rs := strings.Trim(fmt.Sprintf(format, elems...), " \t\n")
	sl := strings.Split(rs, "\n")
	cont := '-'
	for i := range sl {
		if i == len(sl)-1 {
			cont = ' '
		}
		c.reply("%3d%c%s", code, cont, sl[i])
		if c.state == sAbort {
			break
		}
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
	c.conn.SetReadDeadline(time.Now().Add(c.Config.Limits.CmdInput))
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
	c.conn.SetReadDeadline(time.Now().Add(c.Config.Limits.MsgInput))
	c.lr.N = c.Config.Limits.MsgSize
	b, err := c.rdr.ReadDotBytes()
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		b = nil
		c.log("!", "DATA abort %s err: %v",
			fmtBytesLeft(c.Config.Limits.MsgSize, c.lr.N), err)
	} else {
		c.log("r", ". <end of data>")
	}
	return string(b)
}

const authInputLimit = 12288 // recommended by RFC4954

// readAuthResp() reads an RFC4954 authentication response from the
// client; it should be called only in state sAuth. If there is an
// error, state will be set to sAbort.
func (c *Conn) readAuthResp() string {
	c.conn.SetReadDeadline(time.Now().Add(c.Config.Limits.CmdInput))
	c.lr.N = authInputLimit
	line, err := c.rdr.ReadLine()
	if err != nil || c.lr.N == 0 {
		c.state = sAbort
		c.log("!", "auth input abort %s err: %v",
			fmtBytesLeft(authInputLimit, c.lr.N), err)
		return ""
	}
	c.log("r", line)
	return line
}

func (c *Conn) stopme() bool {
	return c.state == sAbort || c.badcmds > c.Config.Limits.BadCmds || c.state == sQuit
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
		c.reply("250 %s Hello %v", c.Config.LocalName, c.conn.RemoteAddr())
	case EHLO:
		c.reply("250-%s Hello %v", c.Config.LocalName, c.conn.RemoteAddr())
		// We advertise 8BITMIME per
		// http://cr.yp.to/smtp/8bitmime.html
		c.replyMore("250-8BITMIME")
		c.replyMore("250-PIPELINING")
		// STARTTLS RFC says: MUST NOT advertise STARTTLS
		// after TLS is on.
		if c.Config.TLSConfig != nil && !c.TLSOn {
			c.replyMore("250-STARTTLS")
		}
		// RFC4954 notes: A server implementation MUST
		// implement a configuration in which it does NOT
		// permit any plaintext password mechanisms, unless
		// either the STARTTLS [SMTP-TLS] command has been
		// negotiated...
		if c.Config.Auth != nil {
			c.replyMore("250-AUTH " + strings.Join(c.authMechanisms(), " "))
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
		c.replyMore("250 HELP")
	case AUTH:
		c.authDone(true)
		c.reply("235 Authentication successful")
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

// AcceptMsg accepts MAIL FROM, RCPT TO, AUTH, DATA, or message bodies
// with the given fmt.Printf style message that you supply. The
// generated message may include embedded newlines for a multi-line
// reply.  This cannot be applied to EHLO/HELO messages; if called for
// one of them, it is equivalent to Accept().
func (c *Conn) AcceptMsg(format string, elems ...interface{}) {
	if c.curcmd == HELO || c.curcmd == EHLO || c.replied {
		// We can't apply to EHLO/HELO because those have
		// special formatting requirements, especially EHLO.
		c.Accept()
		return
	}
	oldstate := c.state
	c.state = c.nstate
	switch c.curcmd {
	case MAILFROM, RCPTTO:
		c.replyMulti(250, format, elems...)
	case AUTH:
		c.authDone(true)
		c.replyMulti(235, format, elems...)
	case DATA:
		if oldstate == sRcpt {
			c.replyMulti(354, format, elems...)
		} else {
			c.replyMulti(250, format, elems...)
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
	case AUTH:
		c.authDone(false)
		c.reply("535 Authentication credentials invalid")
	case DATA:
		c.reply("554 Not accepted")
	}
	c.replied = true
}

// RejectMsg rejects the current SMTP command with the fmt.Printf
// style message that you supply. The generated message may include
// embedded newlines for a multi-line reply.
func (c *Conn) RejectMsg(format string, elems ...interface{}) {
	switch c.curcmd {
	case HELO, EHLO, MAILFROM, RCPTTO:
		c.replyMulti(550, format, elems...)
	case AUTH:
		c.authDone(false)
		c.replyMulti(535, format, elems...)
	case DATA:
		c.replyMulti(554, format, elems...)
	}
	c.replied = true
}

// TempfailMsg temporarily rejects the current SMTP command with
// a 4xx code and the fmt.Printf style message that you supply.
// The generated message may include embedded newlines for a
// multi-line reply.
func (c *Conn) TempfailMsg(format string, elems ...interface{}) {
	switch c.curcmd {
	case HELO, EHLO:
		c.replyMulti(421, format, elems...)
	case AUTH:
		c.authDone(false)
		c.replyMulti(454, format, elems...)
	case MAILFROM, RCPTTO, DATA:
		c.replyMulti(450, format, elems...)
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
	case AUTH:
		c.authDone(false)
		c.reply("454 Temporary authentication failure")
	case MAILFROM, RCPTTO, DATA:
		c.reply("450 Not available")
	}
	c.replied = true
}

// mimeParam() returns true if the parameter argument of a MAIL FROM
// is what we expect for a client exploiting our advertisement of
// 8BITMIME.
func mimeParam(l ParsedLine) bool {
	return l.Cmd == MAILFROM &&
		(l.Params == "BODY=7BIT" || l.Params == "BODY=8BITMIME")
}

// Next returns the next high-level event from the SMTP connection.
//
// Next() guarantees that the SMTP protocol ordering requirements are
// followed and only returns HELO/EHLO, AUTH, MAIL FROM, RCPT TO, and DATA
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
// For the AUTH command, Next() will return a COMMAND event where Arg
// is set to the mechanism requested by the client. The mechanism is
// validated against the list of mechanisms provided in the config.
// The AUTH command event begins an authentication dialog, during
// which one or more AUTHRESP events are returned. The first AUTHRESP
// event contains the initial response from the AUTH command and may
// be empty. The dialog ends if an AUTHABORT or ABORT event is
// returned or when the AUTH command is accepted/rejected. Next will
// not accept the AUTH command automatically. If no reply is sent for
// an AUTHRESP event, the client receives an empty challenge.  Under
// almost all situations you want to respond to a AUTH command not
// directly through calling .Next() but by calling .Authenticate() to
// handle the full details.
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
// offer TLS to that client in the future. No further activity can
// happen on a connection once TLSERROR is returned; the connection is
// considered dead and calling .Next() again will yield an ABORT
// event. The Arg of a TLSERROR event is the TLS error in string form.
func (c *Conn) Next() EventInfo {
	var evt EventInfo

	if c.nextEvent != nil {
		evt = *c.nextEvent
		c.nextEvent = nil
		return evt
	}
	if !c.replied && c.curcmd != noCmd {
		if c.state == sAuth {
			// send empty challenge instead of auto accept
			// to prevent accidental auth success.
			c.AuthChallenge(nil)
		} else {
			c.Accept()
		}
	}
	if c.state == sStartup {
		var announce string
		c.state = sInitial
		// log preceeds the banner in case the banner hits an error.
		c.log("#", "remote %v at %s", c.conn.RemoteAddr(),
			time.Now().Format(TimeFmt))
		if c.Config.Announce != "" {
			announce = "\n" + c.Config.Announce
		}
		if c.Config.SayTime {
			c.replyMulti(220, "%s %s %s%s",
				c.Config.LocalName, c.Config.SftName,
				time.Now().Format(time.RFC1123Z), announce)
		} else {
			c.replyMulti(220, "%s %s%s", c.Config.LocalName,
				c.Config.SftName, announce)
		}
	}

	// Read and parse client AUTH response. Note that AUTH responses
	// are not SMTP commands. During state sAuth, the only events we
	// can return are AUTHRESP, AUTHABORT, and ABORT.
	if c.state == sAuth {
		data := c.readAuthResp()
		if c.state == sAbort {
			evt.What = ABORT
			c.log("#", "abort at %v", time.Now().Format(TimeFmt))
			return evt
		}
		if data == "*" {
			c.authDone(false)
			c.reply("501 Authentication aborted")
			evt.What = AUTHABORT
		} else {
			c.replied = false
			evt.What = AUTHRESP
			evt.Arg = data
		}
		return evt
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
				if c.Config.TLSConfig == nil || c.TLSOn {
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
				c.conn.SetDeadline(time.Now().Add(c.Config.Limits.TLSSetup))
				tlsConn := tls.Server(c.conn, c.Config.TLSConfig)
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
				c.TLSState = tlsConn.ConnectionState()
				if c.TLSState.ServerName != "" {
					c.log("!", "TLS negociated with cipher 0x%04x protocol 0x%04x server name '%s'", c.TLSState.CipherSuite, c.TLSState.Version, c.TLSState.ServerName)
				} else {
					c.log("!", "TLS negociated with cipher 0x%04x protocol 0x%04x", c.TLSState.CipherSuite, c.TLSState.Version)
				}
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

		switch res.Cmd {
		case AUTH:
			if c.Config.Auth == nil {
				c.reply("502 Not supported")
				c.replied = true
				// AUTH with no AUTH enabled counts as a
				// bad command. This deals with a few people
				// who spam AUTH requests at non-supporting
				// servers.
				c.badcmds++
				continue
			}
			if c.authenticated {
				// RFC4954, section 4: After an AUTH
				// command has been successfully
				// completed, no more AUTH commands
				// may be issued in the same session.
				c.reply("503 Out of sequence command")
				c.replied = true
				continue
			}
			if !c.authMechanismValid(res.Arg) {
				c.reply("504 Command parameter not implemented")
				c.replied = true
				continue
			}
			// Queue initial auth response for the next
			// round.  This way, all auth responses are
			// delivered with event type AUTHRESP.
			c.nextEvent = &EventInfo{What: AUTHRESP, Arg: res.Params}
			res.Params = ""
			c.state = sAuth
		case MAILFROM, RCPTTO:
			// Verify that the client has authenticated.
			// We do this here because MAIL FROM is the
			// only valid full state command after
			// HELO/EHLO that requires authentication.
			if c.Config.Auth != nil && !c.authenticated {
				c.reply("530 Authentication required")
				c.replied = true
				continue
			}
			// RCPT TO:<> is invalid; reject it. Otherwise
			// defer all address checking to our callers.
			if res.Cmd == RCPTTO && len(res.Arg) == 0 {
				c.Reject()
				continue
			}
			// reject parameters that we don't accept,
			// which right now is all of them. We reject
			// with the RFC-correct reply instead of a
			// generic one, so we can't use c.Reject().
			if res.Params != "" && c.Config.Limits.NoParams && !mimeParam(res) {
				c.reply("504 Command parameter not implemented")
				c.replied = true
				continue
			}
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
	if c.badcmds > c.Config.Limits.BadCmds {
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

func (c *Conn) authMechanisms() []string {
	// I won't bother checking for nil Auth config here
	// because this is only used when authentication is enabled.
	if c.TLSOn {
		return c.Config.Auth.TLSMechanisms
	}
	return c.Config.Auth.Mechanisms
}

func (c *Conn) authMechanismValid(mech string) bool {
	mech = strings.ToUpper(mech)
	for _, m := range c.authMechanisms() {
		if mech == m {
			return true
		}
	}
	return false
}

// authDone marks a RFC4954 AUTH sequence as being done (whether it
// succeeded or failed). In the process we transition to state sHelo.
func (c *Conn) authDone(success bool) {
	c.replied = true
	c.state = sHelo
	c.nextEvent = nil
	c.authenticated = success
}

// AuthChallenge sends an authentication challenge to the client.
// It only works during authentication.
func (c *Conn) AuthChallenge(data []byte) {
	if c.state != sAuth || c.replied {
		return
	}
	c.reply("334 " + base64.StdEncoding.EncodeToString(data))
	c.replied = true
}

// An AuthFunc implements one step of a SASL authentication dialog.
// The parameter input is the decoded SASL response from the
// client. Each time it's called, the function should either call
// Accept/Reject on the connection or send a challenge using
// AuthChallenge. The input parameter may be nil (the client sent
// absolutely nothing) or empty (the client sent a '=').
//
// TODO: is a completely blank line an RFC error that should cause
// the authentication to fail and the connection to abort?
//
// If an AuthFunc is called and does none of these, it is currently
// equivalent to calling .AuthChallenge(nil). However doing this is
// considered an error, not a guaranteed API, and may someday have
// other effects (eg aborting the authentication dialog).
type AuthFunc func(c *Conn, input []byte)

// Authenticate executes a SASL authentication dialog with the client.
// The given function is invoked until it calls Accept/Reject or the
// client aborts the dialog (or an error happens).
//
// Note that Authenticate() may return after a network error. In
// this case calling Next() will immediately return an ABORT event.
// As a corollary there is no guarantee that your AuthFunc will be
// called even once.
//
// Using a nil AuthFunc is an error. Authenticate() generously doesn't
// panic on you and instead immediately rejects the authentication.
func (c *Conn) Authenticate(mech AuthFunc) (success bool) {
	if mech == nil {
		// ha ha very funny, but let's not panic here.
		c.Reject()
		return false
	}

	for c.state == sAuth {
		switch evt := c.Next(); evt.What {
		case AUTHRESP:
			var input []byte
			switch evt.Arg {
			case "":
				input = nil
			case "=":
				// RFC4954: If the client is
				// transmitting an initial response of
				// zero length, it MUST instead
				// transmit the response as a single
				// equals sign ("="). This indicates
				// that the response is present, but
				// contains no data.
				input = []byte{}
			default:
				var err error
				input, err = base64.StdEncoding.DecodeString(evt.Arg)
				if err != nil {
					// We don't call .Reject()
					// because we want to generate
					// the RFC correct 501 error
					// code.
					c.authDone(false)
					c.reply("501 Invalid authentication response")
					return false
				}
			}
			mech(c, input)

		case AUTHABORT, ABORT:
			return false
		}
	}
	return c.authenticated
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
func NewConn(conn net.Conn, cfg Config, log io.Writer) *Conn {
	c := &Conn{state: sStartup, Config: cfg, logger: log}
	c.setupConn(conn)
	if c.Config.Limits == nil {
		c.Config.Limits = &DefaultLimits
	}
	if c.Config.SftName == "" {
		c.Config.SftName = "go-smtpd"
	}
	if c.Config.LocalName == "" {
		c.Config.LocalName = "localhost"
	}
	return c
}
