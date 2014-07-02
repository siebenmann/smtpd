//
// Flail around testing the rules lexer.
// This cannot be described as comprehensive.

package main

import (
	"fmt"
	"strings"
	"testing"
)

// Test that we can lex all of the constructs we expect without an
// error.
// Run 'go test -v' to see a dump of the lex stream for this block
// of things; it will also be printed if we got an error during
// lexing.
var aLex = `
# this is a comment
accept from a@b.com helo .barney

@message reject to cks@jon.snow
@helo reject helo /a/file host file:something
reject helo somename (from info@fbi.gov or fred@barney) not to i@addr
reject helo-has helo,ehlo,none,nodots,bareip tls on tls off
@from reject dns nodns,inconsistent,noforward address route,quoted,noat
reject helo-has \
	ehlo,none dnsbl fred.jim
reject ip 192.168.0.0/24 ip 127.0.0.2

reject from bad with message from-bad
reject ehlo "fred jim"
`

func TestLexing(t *testing.T) {
	var i item
	var lr []string
	l := lex(aLex)
	t.Log("Parsing result:")
	for {
		i = l.nextItem()
		l1, l2 := l.lineInfo(i.pos)
		lr = append(lr, fmt.Sprintf("%v(%d,%d)", i, l1, l2))
		if i.typ == itemEOL {
			t.Log(strings.Join(lr, " "))
			lr = []string{}
		}
		if i.typ == itemEOF || i.typ == itemError {
			break
		}
	}
	t.Log(strings.Join(lr, " "))
	if i.typ != itemEOF {
		t.Fatalf("lexing did not end with an EOF")
	}
}

type lexTest struct {
	name  string
	input string
	items []item
}

var (
	tEOF   = item{itemEOF, "", 0}
	tComma = item{itemComma, ",", 0}
	tLB    = item{itemLparen, "(", 0}
	tRB    = item{itemRparen, ")", 0}
	tEOL   = item{itemEOL, "\n", 0}
	tSemic = item{itemSemicolon, ";", 0}
)

func itm(s string) item {
	return item{keywords[s], s, 0}
}
func itv(s string) item {
	return item{itemValue, s, 0}
}

// These are not exhaustive by any means.
var lexTests = []lexTest{
	{"empty", "    ", []item{tEOF}},
	{"blank lines", "\n\n\n\n# a comment\n   # more comment\n# run out",
		[]item{tEOF}},
	{"non-keywords", "fred@barney /a/file", []item{
		{itemValue, "fred@barney", 0},
		{itemFilename, "/a/file", 0}, tEOF}},
	{"file:something", "file:something", []item{
		{itemFilename, "file:something", 0}, tEOF}},
	{"file: error", "file:", []item{
		{itemError, "'file:' with no filename", 0}}},
	{"random \\", "\\aback", []item{itv("\\aback"), tEOF}},
	// random string of items.
	{"tls", "tls on tls off\n", []item{itm("tls"), itm("on"),
		itm("tls"), itm("off"), tEOL, tEOF}},
	{"comma ops", "dns nodns,noforward,ehlo", []item{
		itm("dns"), itm("nodns"), tComma, itm("noforward"), tComma,
		itm("ehlo"), tEOF}},
	{"comma bad", ", nodns", []item{tComma, {itemError, "comma followed by whitespace, EOL, or EOF", 0}}},
	{"embedded comment", "stall from @\n # a comment\nreject to @a",
		[]item{itm("stall"), itm("from"), itv("@"), tEOL,
			itm("reject"), itm("to"), itv("@a"), tEOF}},
	// this also tests 'continuing' a blank line
	{"line continuation", " \\\n stall from @ \\\n  to a@b", []item{
		itm("stall"), itm("from"), itv("@"), itm("to"), itv("a@b"),
		tEOF}},
	{"blank continuation in a middle line", "stall from \\\n   \\\n @",
		[]item{itm("stall"), itm("from"), itv("@"), tEOF}},
	{"middle of line backslash", "stall from \\ to a@b", []item{
		itm("stall"), itm("from"), itv("\\"), itm("to"), itv("a@b"),
		tEOF}},

	{"proper quote", "\"fred jim\" from", []item{
		itv("fred jim"), itm("from"), tEOF}},
	{"proper quote with escape", "\"fred\\\"bob\"", []item{
		itv("fred\"bob"), tEOF}},
	{"quote with non-escaping backslash", "\"fred\\bob\"", []item{
		itv("fred\\bob"), tEOF}},
	{"quote defeats comma", "\", \"", []item{itv(", "), tEOF}},
	{"quote spans lines", "\"fred\njim\n  bob\"", []item{
		itv("fred\njim\n  bob"), tEOF}},
	{"unterminated quote", "\"fred jim", []item{
		{itemError, "unterminated quoted value", 0}}},
	{"quote escaping terminator", "\"fred\\\"", []item{
		{itemError, "unterminated quoted value", 0}}},

	{"thing;", "thing;", []item{itv("thing"), tSemic, tEOF}},
}

func collect(input string) (items []item) {
	l := lex(input)
	for {
		item := l.nextItem()
		items = append(items, item)
		if item.typ == itemEOF || item.typ == itemError {
			break
		}
	}
	return
}
func equal(i1, i2 []item) bool {
	if len(i1) != len(i2) {
		return false
	}
	for k := range i1 {
		if i1[k].typ != i2[k].typ || i1[k].val != i2[k].val {
			return false
		}
	}
	return true
}

func TestLex(t *testing.T) {
	for _, test := range lexTests {
		items := collect(test.input)
		if !equal(items, test.items) {
			t.Errorf("%s: got\n\t%+v\nexpected\n\t%+v", test.name, items, test.items)
		}
	}
}

// This is a test that's designed to keep me from making stupid mistakes
// of adding keyword items without adding map entries for them, or adding
// two keyword strings that map to the same itemType.
// It caught one error so VERY USEFUL.
func TestKeywordCover(t *testing.T) {
	m := make(map[itemType]string)
	for k, v := range keywords {
		if m[v] != "" {
			t.Errorf("duplicate entry for %d: %s and %s", v, m[v], k)
		} else {
			m[v] = k
		}
	}
	for i := itemKeywords + 1; i < itemMaxItem; i++ {
		if m[i] == "" {
			t.Errorf("missing keyword string for %d (after %s)", i, m[i-1])
		}
	}
}

// This is a basic invertability test.
func TestAllKeywords(t *testing.T) {
	for kw, kiv := range keywords {
		testitems := []item{{kiv, kw, 0}, tEOF}
		items := collect(kw)
		if !equal(items, testitems) {
			t.Errorf("inversion: got\n\t%+v\nexpected\n\t%+v", items, testitems)
		}
	}
	for kc, kiv := range specials {
		// Because we swallow blank lines, EOL does not invert;
		// it gets plain EOF.
		// EOF does not map to an actual character, so.
		// The lexer specifically errors on ,<EOL|EOF>, so we can't
		// check it either.
		if kiv == itemEOF || kiv == itemEOL || kiv == itemComma {
			continue
		}
		testitems := []item{{kiv, string(kc), 0}, tEOF}
		items := collect(string(kc))
		if !equal(items, testitems) {
			t.Errorf("inversion on %v: got\n\t%+v\nexpected\n\t%+v", kc, items, testitems)
		}
	}
}
