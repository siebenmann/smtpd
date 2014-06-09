// Do proper reverse DNS lookups of IP addresses.
package main

import (
	"net"
	"sort"
)

type rDnsResults struct {
	verified  []string // good, verified reverse DNS names
	nofwd     []string // rDNS name without forward
	inconsist []string // name does not have remote IP as an IP address
}

func LookupAddrVerified(ip string) (r *rDnsResults, err error) {
	r = &rDnsResults{}
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
