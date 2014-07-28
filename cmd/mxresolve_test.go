//
// Do very crude tests of ValidDomain().
//

package main

import (
	"testing"
)

func TestBasicResults(t *testing.T) {
	// Has MX entry
	a := ValidDomain("gmail.com")
	if a != dnsGood {
		t.Fatalf("gmail.com bad: valid %v\n", a)
	}
	// Has A record but no MX (so far, this is crude)
	a = ValidDomain("www.google.com")
	if a != dnsGood {
		t.Fatalf("www.google.com: valid %v\n", a)
	}

	// No such thing.
	a = ValidDomain("nosuchdomain.fred")
	if a != dnsBad {
		t.Fatalf("nosuchdomain.fred: valid %v\n", a)
	}
}
