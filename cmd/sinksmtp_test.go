//
package main

import (
	"bufio"
	"strings"
	"testing"
)

func TestLoader(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(basiclist))
	a, err := readList(reader)
	if err != nil {
		t.Fatalf("Error during read: %#v", err)
	}
	for _, p := range present {
		if !a[p] {
			t.Fatalf("Missing a record: %s", p)
		}
	}
	if a[""] {
		t.Fatalf("Blank line present in address list.")
	}
	if a["# t"] {
		t.Fatalf("Comment present in address list.")
	}
}

var basiclist = `# This is a comment
INFO@FBI.GOV
root@

@example.com
postmaster@Example.Org
@.barney.net
# t
`
var present = []string{
	"info@fbi.gov", "root@", "@example.com", "postmaster@example.org",
}

func TestNilAlist(t *testing.T) {
	if inAddrList("abc", nil, false) {
		t.Errorf("Nil addrlist fails default case of false")
	}
	if !inAddrList("def", nil, true) {
		t.Errorf("Nil addrlist fails default case of true")
	}
}

func TestMatching(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(basiclist))
	a, err := readList(reader)
	if err != nil {
		t.Fatalf("Error during read: %#v", err)
	}
	for _, in := range inAddrs {
		if !inAddrList(in, a, false) {
			t.Errorf("Addrlist does not match %s", in)
		}
	}
	for _, out := range outAddrs {
		if inAddrList(out, a, true) {
			t.Errorf("Addrlist incorrectly matches %s", out)
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
