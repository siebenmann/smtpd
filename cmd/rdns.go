// Do proper reverse DNS lookups of IP addresses.
package main

import (
	"net"
	"sort"
)

func LookupAddrVerified(ip string) (names []string, verified []string, err error) {
	if ip == "" {
		return names, verified, nil
	}
	names, err = net.LookupAddr(ip)
	sort.Strings(names)
	if err != nil {
		return names, verified, err
	}
	eip := net.ParseIP(ip)
	for _, name := range names {
		addrs, err := net.LookupIP(name)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if addr.Equal(eip) {
				verified = append(verified, name)
			}
		}
	}
	return names, verified, nil
}
