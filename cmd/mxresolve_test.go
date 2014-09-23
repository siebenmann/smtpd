//
// Do very crude tests of ValidDomain().
//

package main

import (
	"testing"
)

func TestBasicResults(t *testing.T) {
	// Has MX entry
	a, err := ValidDomain("gmail.com")
	if a != dnsGood || err != nil {
		t.Fatalf("gmail.com bad: valid %v / %v\n", a, err)
	}
	// Has A record but no MX (so far, this is crude)
	a, err = ValidDomain("www.google.com")
	if a != dnsGood || err != nil {
		t.Fatalf("www.google.com: valid %v / %v\n", a, err)
	}

	// No such thing.
	a, err = ValidDomain("nosuchdomain.fred")
	if a != dnsBad || err == nil {
		t.Fatalf("nosuchdomain.fred: valid %v / %v\n", a, err)
	}
}
