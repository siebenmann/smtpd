//
//
package smtpd

import (
	"fmt"
	"strings"
)

// An enumeration of SMTP commands that we recognize, plus BadCmd for
// 'no such command'.
type Command int

const (
	NoCmd Command = iota // artificial zero value
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
	// TODO: do I need any additional SMTP commands?
}

// Turn a Command int into a string for debugging et al.
func (v Command) String() string {
	switch v {
	case NoCmd:
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

	// All valid SMTP commands are either four characters long or have
	// a space as the fifth character. We do a fast-path check here for
	// this.
	llen := len(line)
	if llen < 4 || (llen > 4 && line[4] != ' ') {
		res.err = "bad command"
		return res
	}

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
