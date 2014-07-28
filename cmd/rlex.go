//
// Lexer for control rules.
// See rules.go.
//
// The structure of this lexer is cribbed wholesale from Rob Pike's
// lexer for templates in text/template/parse/lex.go (and in a slide
// deck I read) and then mutilated by my lack of understanding of how
// to do it nicely. TODO: clean up, make nicer, etc.
//
// The basic structure is that the lexer state is not represented
// explicitly with a state index but is implicit in what function
// is processing input. We change states by returning different
// functions to switch to and end processing by returning nil.
//
// Note that this does *no* validity checking. We do not have any idea of,
// say, 'unterminated ('; that's for higher levels to insist on. The only
// time we might do that is if we had quoted values, but we don't right
// now.
// (Okay, we do need to do one check: commas cannot be followed by
// whitespace. Since we are silent about whitespace, the higher level
// can't tell whether or not it was present after a comma.)
//
// A final newline in the input is optional; we take EOF as an implicit
// EOL. Well, the parser does. I suppose we could create a fake EOL if
// we wanted to but we don't do that yet.

package main

import (
	"fmt"
	"strings"
)

// parsing and lexing in go:
// http://cuddle.googlecode.com/hg/talk/lex.html
// http://golang.org/cmd/yacc/

// Lexing: we don't have keywords as such, because keywords would require
// reserved words that cannot be addresses et al. Lexing yields words or
// ( ) , or EOL markers (and EOF).
// We generate 'keywords', but these may be interpreted either as real
// keywords or their string value by higher levels depending on the
// context.

type item struct {
	typ itemType
	val string
	pos int // position of the start of this item in the input stream
}
type itemType int

// Some words serve multiple duties, eg 'helo' is all of a phase,
// a rule operation, and an option. They occur once in the set of
// keyword item types. We disambiguate what they mean based on context.
const (
	itemError itemType = iota
	// markers
	itemEOF
	itemEOL

	// this marks the start of items that have a valid value.
	itemHasValue

	// punctuation:
	itemComma
	itemLparen
	itemRparen
	itemSemicolon

	// general values
	itemValue
	itemFilename

	// This marks the start of item keywords. All values higher
	// than this do double duty; depending on context they may
	// be either actual keywords or values that happen to match
	// keywords.
	itemKeywords

	// All of the sorts of keywords:
	itemInclude

	// phases
	itemAHelo
	itemAFrom
	itemATo
	itemAData
	itemAMessage

	// core operations
	itemAccept
	itemReject
	itemStall
	itemSetWith

	// expression bits
	itemOr
	itemNot

	// rule keywords not already mentioned
	itemHelo
	itemAll
	itemFrom
	itemTo
	itemFromHas
	itemToHas
	itemHeloHas
	itemTls
	itemHost
	itemDns
	itemIp
	itemDnsbl

	// add-ons
	itemWith
	itemMessage
	itemNote
	itemSavedir

	// options that do not duplicate keywords
	itemEhlo
	itemNone
	itemNodots
	itemBareip
	itemProperip
	itemMyip
	itemRemip
	itemOtherip
	itemNodns
	itemInconsistent
	itemNoforward
	itemUnqualified
	itemRoute
	itemQuoted
	itemNoat
	itemGarbage
	itemDomainValid
	itemDomainInvalid
	itemDomainTempfail
	itemBad
	itemOn
	itemOff
	itemGood
	itemExists

	// highest keyword, well, one larger than it.
	itemMaxItem
)

// issue: we have a lot of item types here. Really, a lot.

var keywords = map[string]itemType{
	"include": itemInclude,

	// phases
	"@helo":    itemAHelo,
	"@from":    itemAFrom,
	"@to":      itemATo,
	"@data":    itemAData,
	"@message": itemAMessage,

	// actions
	"accept":   itemAccept,
	"reject":   itemReject,
	"stall":    itemStall,
	"set-with": itemSetWith,

	// ops
	"or":  itemOr,
	"not": itemNot,

	// rule operations
	"all":      itemAll,
	"from":     itemFrom,
	"to":       itemTo,
	"helo":     itemHelo,
	"host":     itemHost,
	"from-has": itemFromHas,
	"to-has":   itemToHas,
	"helo-has": itemHeloHas,
	"tls":      itemTls,
	"dns":      itemDns,
	"ip":       itemIp,
	"dnsbl":    itemDnsbl,

	// add-ons
	"with":    itemWith,
	"message": itemMessage,
	"note":    itemNote,
	"savedir": itemSavedir,

	// options
	"ehlo":         itemEhlo,
	"none":         itemNone,
	"nodots":       itemNodots,
	"bareip":       itemBareip,
	"properip":     itemProperip,
	"myip":         itemMyip,
	"remip":        itemRemip,
	"otherip":      itemOtherip,
	"nodns":        itemNodns,
	"inconsistent": itemInconsistent,
	"noforward":    itemNoforward,
	"unqualified":  itemUnqualified,
	"route":        itemRoute,
	"quoted":       itemQuoted,
	"noat":         itemNoat,
	"garbage":      itemGarbage,
	"resolves":     itemDomainValid,
	"baddom":       itemDomainInvalid,
	"unknown":      itemDomainTempfail,
	"bad":          itemBad,
	"on":           itemOn,
	"off":          itemOff,
	"good":         itemGood,
	"exists":       itemExists,
}

const eof = -1

func (i item) String() string {
	switch {
	case i.typ == itemEOF:
		return "EOF"
	case i.typ == itemEOL:
		return "EOL"
	case i.typ == itemError:
		return fmt.Sprintf("ERROR:'%s'", i.val)
	case i.typ == itemValue:
		return fmt.Sprintf("\"%s\"", i.val)
	case i.typ == itemFilename:
		return fmt.Sprintf("<file %s>", i.val)
	default:
		return fmt.Sprintf("<op %d:%s>", i.typ, i.val)
	}
}

var specials = map[int]itemType{
	',':  itemComma,
	'(':  itemLparen,
	')':  itemRparen,
	';':  itemSemicolon,
	'\n': itemEOL,
	eof:  itemEOF,
}

const specialChars = "(),;\n \t" // actual characters from above and whitespace

type stateFn func(*lexer) stateFn

type lexer struct {
	input string
	state stateFn
	pos   int // current position in input
	start int // start of current token/scan thing in input
	width int // amount to back up on .backup(); 0 at EOF
	items chan item
}

// return next character, consuming it by advancing input position
func (l *lexer) next() int {
	if l.pos >= len(l.input) {
		l.width = 0
		return eof
	}
	r := l.input[l.pos]
	l.width = 1
	l.pos += l.width
	return int(r)
}

// reverse the effect of .next(). we need l.width so that we don't back
// up one character when .next() returned EOF.
func (l *lexer) backup() {
	l.pos -= l.width
}

// peek at current character without consuming it
func (l *lexer) peek() int {
	r := l.next()
	l.backup()
	return r
}

// swallow the current token
func (l *lexer) swallow() {
	l.start = l.pos
}

// emit the current token to the lexer channel
func (l *lexer) emit(t itemType) {
	l.items <- item{t, l.input[l.start:l.pos], l.start}
	l.start = l.pos
}

// emit a given fully specified token to the lexer channel
// this is used to emit quoted strings.
func (l *lexer) emitString(t itemType, s string) {
	l.items <- item{t, s, l.start}
	l.start = l.pos
}

// emit an error to the lexer channel *AND* return nil as the next
// lexer step. This is a hybrid function
func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- item{itemError, fmt.Sprintf(format, args...), l.start}
	return nil
}

// run the internal lexer to lex input until we're done or things explode
func (l *lexer) run() {
	for l.state = lexLineStart; l.state != nil; {
		l.state = l.state(l)
	}
}

// get the next token from the lexer channel
func (l *lexer) nextItem() item {
	item := <-l.items
	return item
}

// returns the line number and the byte position within the line,
// both starting from 1. The position of EOF is not entirely
// meaningful.
// This is not particularly efficient but lineInfo() is expected
// to be called infrequently, only on errors.
func (l *lexer) lineInfo(pos int) (lnum int, lpos int) {
	lnum = 1 + strings.Count(l.input[:pos], "\n")
	for i := pos - 1; i >= 0 && l.input[i] != '\n'; i-- {
		lpos++
	}
	return lnum, 1 + lpos
}

// Given a string, create and return a lexer for it. Callers then
// call l.nextItem() until it returns EOF or an error.
func lex(input string) *lexer {
	l := &lexer{
		input: input,
		items: make(chan item),
	}
	go l.run()
	return l
}

//
// Internal lexer state functions

// silently skip over whitespace, if any.
// this is not a state function but it is called by state functions.
func skipWhitespace(l *lexer) {
	for {
		r := l.next()
		if !(r == ' ' || r == '\t') {
			l.backup()
			l.swallow()
			return
		}
	}
}

// A special character, including EOF. Positioned at the character.
// l.start == l.pos at entry.
// We peek at the character after commas to disallow ',<whitespace>'
// as the parser can't see the difference between ',X' and ', X'.
func lexSpecial(l *lexer) stateFn {
	r := l.next()
	l.emit(specials[r])
	n := l.peek()
	switch r {
	case '\n':
		// reset to start of line.
		return lexLineStart
	case eof:
		return nil
	case ',':
		// Only ', <whitespace>' can silently fall through the
		// cracks because we swallow whitespace. Everything else
		// generates explicit tokens and so will throw a parse
		// error.
		// Technically we don't have to check for EOL or EOF
		// because the parser will error out since those are
		// distinct tokens, but I think it gives better error
		// messages to fail the lexing here (or at least it
		// makes them easier).
		// TODO: this is really the wrong handling of comma.
		// Comma by itself should be left alone and we should do
		// special treatment only of 'word,< |\t|\n|EOF>'.
		// As it is we've turned comma into a very special thing
		// that cannot be used as an ordinary value under almost
		// any circumstance; instead you have to quote it.
		if n == ' ' || n == '\t' || n == '\n' || n == eof {
			l.backup()
			return l.errorf("comma followed by whitespace, EOL, or EOF")
		}
		return lexLineRunning
	default:
		return lexLineRunning
	}
}

// A 'word', delimited by whitespace, EOL, EOF, or a special character.
// The word has at least one character by assumption.
// l.start == l.pos at entry
func lexWord(l *lexer) stateFn {
	idx := strings.IndexAny(l.input[l.pos:], specialChars)
	if idx < 0 {
		// no stop characters? string runs right to end of input
		idx = len(l.input) - l.pos
	}
	l.pos += idx

	// determine keyword, filename, or plain value.
	v := l.input[l.start:l.pos]
	switch {
	case keywords[v] != itemError:
		l.emit(keywords[v])
	case v[0] == '/' || strings.HasPrefix(v, "./"):
		l.emit(itemFilename)
	case strings.HasPrefix(v, "file:"):
		if len(v) <= len("file:") {
			return l.errorf("'file:' with no filename")
		}
		l.emit(itemFilename)
	default:
		l.emit(itemValue)
	}

	return lexLineRunning
}

// Lex a quote. Within a quote, \" translates to ".
// We enter lexQuote with the starting " *not* consumed.
// Quotes are always itemValues.
// TODO: this is probably a bad algorithm, but it is what it is.
func lexQuote(l *lexer) stateFn {
	// qparts is used to accumulate chunks of quoted input. We use
	// it to properly handle quoted "'s, ie \", which must be rewritten
	// to ".
	var qparts []string
	var lookat int

	// advance past quote. we don't eat the quote with l.swallow()
	// because we want our start position to point to it until the
	// whole thing has been successfully processed; this way the
	// right start position will appear in emitted items.
	l.next()

	lookat = l.pos
	for {
		// EOF check
		if lookat >= len(l.input) {
			break
		}
		// does the quote just run to EOF?
		idx := strings.IndexAny(l.input[lookat:], "\\\"")
		if idx == -1 {
			break
		}
		// okay, we can look at what we found
		apos := lookat + idx

		// end of quote
		if l.input[apos] == '"' {
			qparts = append(qparts, l.input[l.pos:apos])
			l.pos = apos + 1
			l.emitString(itemValue, strings.Join(qparts, ""))
			return lexLineRunning
		}

		// possible quoted string or quoted escape. Check.
		// If not, skip it.
		if !(strings.HasPrefix(l.input[apos:], "\\\"") || strings.HasPrefix(l.input[apos:], "\\\\")) {
			lookat = apos + 1
			continue
		}

		// real \" or \\ sequence; eat it
		qparts = append(qparts, l.input[l.pos:apos])
		qparts = append(qparts, l.input[apos+1:apos+2])
		l.pos = apos + 2
		lookat = l.pos
	}

	// this is our error case.
	l.errorf("unterminated quoted value")
	return nil
}

// Within a line, move forward to the next non-whitespace and dispatch
// to handling either a special or a word. We also eat line continuations
// (which must be literally \<newline>, no whitespace between the two).
// Note that line continuations must have whitespace before them.
func lexLineRunning(l *lexer) stateFn {
	skipWhitespace(l)
	r := l.peek()
	switch {
	case r == '\\' && strings.HasPrefix(l.input[l.pos:], "\\\n"):
		l.pos += 2
		l.swallow()
		return lexLineRunning
	case specials[r] != itemError:
		return lexSpecial
	case r == '"':
		return lexQuote
	default:
		return lexWord
	}
}

// Eat a comment to end of line or EOF.
func lexComment(l *lexer) stateFn {
	idx := strings.IndexByte(l.input[l.pos:], '\n')
	if idx < 0 {
		idx = len(l.input) - l.pos
	}
	l.pos += idx
	l.swallow()
	return lexLineStart
}

// Dispatch the start of a line. Skip whitespace then peek at the next
// character for what to do: newline (we swallow the blank line),
// comment start (go off to eat comment), special characters
// (dispatch), and otherwise it must be a regular word and goes to
// lexWord.
// Unlike other things, lexLineStart does not consume the first character
// it looks at; it merely peeks.
func lexLineStart(l *lexer) stateFn {
	skipWhitespace(l)
	r := l.peek()
	if r != '\n' && specials[r] != itemError {
		return lexSpecial
	}
	switch r {
	case '"':
		return lexQuote
	case '#':
		l.next()
		return lexComment
	case '\\':
		// We basically treat continuations at the end of empty
		// lines as if they were fully blank lines, because that
		// seems like the best option.
		if strings.HasPrefix(l.input[l.pos:], "\\\n") {
			l.pos += 2
			l.swallow()
			return lexLineStart
		}
		return lexWord
	case '\n':
		// We swallow blank lines instead of feeding higher
		// levels a stream of itemEOLs.
		l.next()
		l.swallow()
		return lexLineStart
	default:
		return lexWord
	}
}
