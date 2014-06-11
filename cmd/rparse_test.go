//
// Test parsing and some evaluating
// TODO: more tests
//
package main

import (
	"fmt"
	"github.com/siebenmann/smtpd"
	"testing"
)

var aParse = `
accept from a@b
@data reject to b@c or to fred or from a@b helo barney
stall from a@b not to d@e or (helo barney to charlie host fred)
reject helo somename from info@fbi.gov not to interesting@addr
reject helo-with none,nodots,helo from-has bad,quoted dns nodns
@message reject to-has garbage,route
accept dns good
reject dns noforward,inconsistent

# test all options for comma-separated things.
accept dns good or dns noforward,inconsistent,nodns
accept tls on or tls off
accept from-has unqualified,route,quoted,noat,garbage,bad
accept to-has unqualified,route,quoted,noat,garbage,bad
accept helo-with helo,ehlo,none,nodots,bareip

`

func TestParse(t *testing.T) {
	rules, err := Parse(aParse + allSuccess)
	if err != nil {
		t.Fatalf("Error reported: %s\n", *err)
	}
	if len(rules) == 0 {
		t.Fatalf("No parse error but nothing found")
	}
	for i := range rules {
		r1 := stringRule(rules[i])
		rls, err := Parse(r1)
		if err != nil || len(rls) != 1 {
			t.Fatalf("round tripping: %s\nerr: %s\nrules: %+v\n",
				r1, *err, rls)
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
accept helo-with ehlo tls on
accept not helo-with nodots from @.net or dns nodns or to @.com
accept helo-with nodots or (from @jones.com to @example.com)
accept from jim@jones.com to info@fbi.gov or to joe@example.com
accept not (from jim@ to @logan)
# dns is not good because there are inconsistent and noforward stuff
accept not dns good
`

func TestSuccess(t *testing.T) {
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
	}
	rules, err := Parse(allSuccess)
	if err != nil {
		t.Fatalf("error reported %s\n", *err)
	}
	for i := range rules {
		res := rules[i].expr.Eval(c)
		if !res {
			t.Errorf("rule did not succeed: %v\n", rules[i].expr)
		}
	}
}
