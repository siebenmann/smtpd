//
package main

import (
	"fmt"
	"testing"
)

var aParse = `
accept from a@b
data reject to b@c or to fred or from a@b helo barney
stall from a@b not to d@e or (helo barney to charlie host fred)
reject helo somename from info@fbi.gov not to interesting@addr
`

func TestParse(t *testing.T) {
	rules, err := Parse(aParse)
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
		fmt.Printf("%s\n", rules[i].String())
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
