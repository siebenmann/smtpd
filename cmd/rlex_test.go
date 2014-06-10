//
// Flail around testing the rules lexer.
// This cannot be described as comprehensive.

package main

import (
	"fmt"
	"testing"
)

var aLex = `
# this is a comment
accept from a@b.com helo .barney

message reject to cks@jon.snow
helo reject helo /a/file
reject helo somename (from info@fbi.gov or fred@barney) not to i@addr
reject greeted helo,ehlo,none,nodots,bareip tls on tls off
mailfrom reject dns nodns,inconsistent,noforward address route,quoted,noat

reject address bad`

// this function is used to dump the lex stream of a basic parse
// it's usually off ('test' lower case).
func testLexing(t *testing.T) {
	l := lex(aLex)
	fmt.Printf("Parsing result:\n")
	for {
		i := l.nextItem()
		l1, l2 := l.lineInfo(i.pos)
		fmt.Printf(" %v(%d,%d)", i, l1, l2)
		if i.typ == itemEOF {
			break
		}
	}
	fmt.Printf("\n")
}

type lexTest struct {
	name  string
	input string
	items []item
}

var (
	tEOF   = item{itemEOF, "", 0}
	tComma = item{itemComma, ",", 0}
	tLB    = item{itemLbracket, "(", 0}
	tRB    = item{itemRbracket, ")", 0}
	tEOL   = item{itemEOL, "\n", 0}
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
		item{itemValue, "fred@barney", 0},
		item{itemFilename, "/a/file", 0}, tEOF}},
	// random string of items.
	{"tls", "tls on tls off\n", []item{itm("tls"), itm("on"),
		itm("tls"), itm("off"), tEOL, tEOF}},
	{"comma ops", "dns nodns,noforward,ehlo", []item{
		itm("dns"), itm("nodns"), tComma, itm("noforward"), tComma,
		itm("ehlo"), tEOF}},
	{"comma bad", ", nodns", []item{tComma, item{itemError, "comma followed by whitespace", 0}}},
	{"embedded comment", "stall from @\n # a comment\nreject to @a",
		[]item{itm("stall"), itm("from"), itv("@"), tEOL,
			itm("reject"), itm("to"), itv("@a"), tEOF}},
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
		testitems := []item{item{kiv, kw, 0}, tEOF}
		items := collect(kw)
		if !equal(items, testitems) {
			t.Errorf("inversion: got\n\t%+v\nexpected\n\t%+v", items, testitems)
		}
	}
	for kc, kiv := range specials {
		// Because we swallow blank lines, EOL does not invert;
		// it gets plain EOF.
		// EOF does not map to an actual character, so.
		if kiv == itemEOF || kiv == itemEOL {
			continue
		}
		testitems := []item{item{kiv, string(kc), 0}, tEOF}
		items := collect(string(kc))
		if !equal(items, testitems) {
			t.Errorf("inversion on %v: got\n\t%+v\nexpected\n\t%+v", kc, items, testitems)
		}
	}
}
