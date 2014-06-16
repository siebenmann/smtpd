//
package main

// Do proper reverse DNS lookups of IP addresses.

import (
	"net"
	"sort"
)

type rDNSResults struct {
	verified  []string // good, verified reverse DNS names
	nofwd     []string // rDNS name without forward
	inconsist []string // name does not have remote IP as an IP address
}

// LookupAddrVerified looks up the names of an IP address and verifies
// them, returning information about both verified names and names that
// failed verification for various reasons.
func LookupAddrVerified(ip string) (r *rDNSResults, err error) {
	r = &rDNSResults{}
	if ip == "" {
		return r, nil
	}
	names, err := net.LookupAddr(ip)
	sort.Strings(names)
	if err != nil {
		return r, err
	}
	eip := net.ParseIP(ip)
	for _, name := range names {
		addrs, err := net.LookupIP(name)
		if err != nil {
			r.nofwd = append(r.nofwd, name)
			continue
		}
		verified := false
		for _, addr := range addrs {
			if addr.Equal(eip) {
				r.verified = append(r.verified, name)
				verified = true
				break
			}
		}
		if !verified {
			r.inconsist = append(r.inconsist, name)
		}
	}
	return r, nil
}
