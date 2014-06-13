//
// Test parsing and some evaluating
// TODO: more tests
//
package main

import (
	"bufio"
	"fmt"
	"github.com/siebenmann/smtpd"
	"strings"
	"testing"
)

var aParse = `
accept from a@b
@data reject to b@c or to fred or from a@b helo barney
stall from a@b not to d@e or (helo barney to charlie host fred)
reject helo somename from info@fbi.gov not to interesting@addr
reject helo-has none,nodots,helo from-has bad,quoted dns nodns
@message reject to-has garbage,route
accept dns good
reject dns noforward,inconsistent

# test all options for comma-separated things.
accept dns good or dns noforward,inconsistent,nodns or dns exists
accept tls on or tls off
accept from-has unqualified,route,quoted,noat,garbage,bad
accept to-has unqualified,route,quoted,noat,garbage,bad
accept helo-has helo,ehlo,none,nodots,bareip

`

func TestParse(t *testing.T) {
	rules, err := Parse(aParse + allSuccess)
	if err != nil {
		t.Fatalf("Error reported: %s\n", err)
	}
	if len(rules) == 0 {
		t.Fatalf("No parse error but nothing found")
	}
	for i := range rules {
		r1 := stringRule(rules[i])
		rls, err := Parse(r1)
		if err != nil || len(rls) != 1 {
			t.Fatalf("round tripping: %s\nerr: %s\nrules: %+v\n",
				r1, err, rls)
		}
		r2 := stringRule(rls[0])
		if r2 != r1 {
			t.Fatalf("failed to round trip.\nstart:\t%s\nend:\t%s\n", r1, r2)
		}
		//fmt.Printf("%s\n", rules[i].String())
	}
}

// This should be round-trippable.
func stringRule(r *Rule) string {
	if r.deferto != pAny {
		return fmt.Sprintf("%v %v %s", r.deferto, r.result,
			r.expr.String())
	} else {
		return fmt.Sprintf("%v %s", r.result, r.expr.String())
	}
}

var allSuccess = `
accept all
accept from jim@jones.com to joe@example.com not dns nodns
accept to joe@ from @.com
accept dns inconsistent dns noforward
accept helo-has ehlo tls on
accept not helo-has nodots from @.net or dns nodns or to @.com
accept helo-has nodots or (from @jones.com to @example.com)
accept from jim@jones.com to info@fbi.gov or to joe@example.com
accept not (from jim@ to @logan)
# dns is not good because there are inconsistent and noforward stuff
accept not dns good
accept helo .ben
accept not helo-has bareip
`

var aList = `# This is a comment
INFO@FBI.GOV
root@

@example.com
postmaster@Example.Org
@.barney.net
# t
`

func setupContext(t *testing.T) *Context {
	rd := &rDnsResults{[]string{"a.b.c", "d.e.f"}, []string{"g"},
		[]string{"h.i"}}
	st := &smtpTransaction{
		rdns:  rd,
		tlson: true,
	}
	c := &Context{trans: st,
		helocmd:  smtpd.EHLO,
		heloname: "joebob.ben",
		from:     "jim@jones.com",
		rcptto:   "joe@example.com",
		files:    make(map[string][]string),
	}

	reader := bufio.NewReader(strings.NewReader(aList))
	a, err := readList(reader)
	if err != nil {
		t.Fatalf("Error during read: %#v", err)
	}
	c.files["/a/file"] = a
	return c
}

func TestSuccess(t *testing.T) {
	c := setupContext(t)
	rules, err := Parse(allSuccess)
	if err != nil {
		t.Fatalf("error reported %s\n", err)
	}
	for i := range rules {
		res := rules[i].expr.Eval(c)
		if !res {
			t.Errorf("rule did not succeed: %v\n", rules[i].expr)
		}
	}
}

var inAddrs = []string{
	"INFO@FBI.GOV", "root@fred.com", "random@example.com",
	"postmaster@example.org", "root@example.com",
	"joe@fred.barney.net", "james@barney.net",
}
var outAddrs = []string{
	"fred@fbi.gov", "postmaster@example.net", "fred@random.org",
	"nosuch@james.net", "nosuch@barney.org",
}

func TestFileAddrMatching(t *testing.T) {
	c := setupContext(t)
	rules, e := Parse("accept from /a/file")
	if e != nil {
		t.Fatalf("parse error %v", e)
	}
	for _, in := range inAddrs {
		c.from = in
		if !rules[0].expr.Eval(c) {
			t.Errorf("address list does not match %s", in)
		}
	}
	for _, out := range outAddrs {
		c.from = out
		if rules[0].expr.Eval(c) {
			t.Errorf("address list matches %s", out)
		}
	}
}
