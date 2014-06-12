//
// Lexer for processing rules.
// See rules.go.
//
// The structure of this lexer is cribbed wholesale from Rob Pike's
// lexer for templates in text/template/parse/lex.go (and in a slide
// deck I read) and then mutilated by my lack of understanding of how
// to do it nicely. TODO: clean up, make nicer, etc.
//
// Note that this does *no* validity checking. We do not have any idea of,
// say, 'unterminated ('; that's for higher levels to insist on. The only
// time we might do that is if we had quoted values, but we don't right
// now.
// (Okay, we do need to do one check: commas cannot be followed by
// whitespace.)
//
// A final newline is optional.
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

	// general values
	itemValue
	itemFilename

	// This marks the start of item keywords. All values higher
	// than this do double duty; depending on context they may
	// be either actual keywords or values that happen to match
	// keywords.
	itemKeywords

	// All of the sorts of keywords:
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

	// options that do not duplicate keywords
	itemEhlo
	itemNone
	itemNodots
	itemBareip
	itemNodns
	itemInconsistent
	itemNoforward
	itemUnqualified
	itemRoute
	itemQuoted
	itemNoat
	itemGarbage
	itemBad
	itemOn
	itemOff
	itemGood

	// highest keyword, well, one larger than it.
	itemMaxItem
)

// issue: we have a lot of item types here. Really, a lot.

var keywords = map[string]itemType{
	// phases
	"@helo":    itemAHelo,
	"@from":    itemAFrom,
	"@to":      itemATo,
	"@data":    itemAData,
	"@message": itemAMessage,
	// actions
	"accept": itemAccept,
	"reject": itemReject,
	"stall":  itemStall,
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
	// options
	"ehlo":         itemEhlo,
	"none":         itemNone,
	"nodots":       itemNodots,
	"bareip":       itemBareip,
	"nodns":        itemNodns,
	"inconsistent": itemInconsistent,
	"noforward":    itemNoforward,
	"unqualified":  itemUnqualified,
	"route":        itemRoute,
	"quoted":       itemQuoted,
	"noat":         itemNoat,
	"garbage":      itemGarbage,
	"bad":          itemBad,
	"on":           itemOn,
	"off":          itemOff,
	"good":         itemGood,
}

const eof = -1

func (i item) String() string {
	switch {
	case i.typ == itemEOF:
		return "EOF"
	case i.typ == itemEOL:
		return "EOL\n"
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
	'\n': itemEOL,
	eof:  itemEOF,
}

const specialChars = "(),\n \t" // actual characters from above and whitespace

type stateFn func(*lexer) stateFn

type lexer struct {
	input string
	state stateFn
	pos   int
	start int
	width int
	items chan item
}

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

func (l *lexer) backup() {
	l.pos -= l.width
}

func (l *lexer) peek() int {
	r := l.next()
	l.backup()
	return r
}
func (l *lexer) swallow() {
	l.start = l.pos
}

func (l *lexer) emit(t itemType) {
	l.items <- item{t, l.input[l.start:l.pos], l.start}
	l.start = l.pos
}

func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- item{itemError, fmt.Sprintf(format, args...), l.start}
	return nil
}

func (l *lexer) run() {
	for l.state = lexLineStart; l.state != nil; {
		l.state = l.state(l)
	}
}

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
		lpos += 1
	}
	return lnum, 1 + lpos
}

func lex(input string) *lexer {
	l := &lexer{
		input: input,
		items: make(chan item),
	}
	go l.run()
	return l
}

// silently skip over whitespace, if any.
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
		if n == ' ' || n == '\t' {
			l.backup()
			return l.errorf("comma followed by whitespace")
		} else {
			return lexLineRunning
		}
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
	case v[0] == '/' || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "file"):
		l.emit(itemFilename)
	default:
		l.emit(itemValue)
	}

	return lexLineRunning
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
	default:
		return lexWord
	}
}

// Eat the comment to end of line or EOF.
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
		} else {
			return lexWord
		}
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
