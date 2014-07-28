//
// Determine if a domain name is a valid mail domain.
// This is not in the smtpd package because right now we have to do
// crazy things to determine temporary DNS failures from permanent ones.
// The problem is that DNSError.Temporary() is only true for timeout
// errors from the local DNS resolver; if the local DNS resolver returns
// a SERVFAIL result, Temporary() is *false* right now. Sigh. This leaves
// us with the fragile approach of inspecting the actual error string.

package main

import (
	"fmt"
	"net"
	"strings"
)

type dnsResult int

const (
	dnsUndef dnsResult = iota
	dnsGood
	dnsBad
	dnsTempfail
)

func (d dnsResult) String() string {
	switch d {
	case dnsUndef:
		return "<dns-undef>"
	case dnsGood:
		return "<dns-good>"
	case dnsBad:
		return "<dns-bad>"
	case dnsTempfail:
		return "<dns-tempfail>"
	default:
		return fmt.Sprintf("<dns-%d>", d)
	}
}

// this is extremely ugly, but the net.DNSError code gives us
// no better way. serverrstr is the exact error string that
// src/pkg/net/dnsclient.go uses in answer() if the server returns
// anything but dnsRcodeSuccess or dnsRcodeNameError, and in particular
// when the rcode is dnsRcodeServerFailure (aka SERVFAIL, aka what DNS
// servers return if eg they can't talk to any of the authoritative
// servers).
var serverrstr = "server misbehaving"

// TODO: create an interface for .Temporary() and coerce the error
// to it, to pick up all net.* errors with Temporary().
// ... well, that would be DNSError and the internal timeout
// error, so there may not be much point to that.
func isTemporary(err error) bool {
	if e, ok := err.(*net.DNSError); ok {
		if e.Temporary() || e.Err == serverrstr {
			return true
		}
	}
	return false
}

// See http://en.wikipedia.org/wiki/Private_network#Private_IPv4_address_spaces
// TODO: Maybe we should exclude link-local addresses too?
var _, net10, _ = net.ParseCIDR("10.0.0.0/8")
var _, net172, _ = net.ParseCIDR("172.16.0.0/12")
var _, net192, _ = net.ParseCIDR("192.168.0.0/16")
var _, ipv6private, _ = net.ParseCIDR("FC00::/7")
var _, ipv6siteloc, _ = net.ParseCIDR("FEC0::/10")

// checkIP checks an IP to see if it is a valid mail delivery target.
// A valid mail delivery target must have at least one IP address and
// all of its IP addresses must be global unicast IP addresses (not
// localhost IPs, not multicast, etc).
func checkIP(domain string) dnsResult {
	addrs, err := net.LookupIP(domain)
	if err != nil && isTemporary(err) {
		return dnsTempfail
	}
	if err != nil {
		return dnsBad
	}
	if len(addrs) == 0 {
		return dnsBad
	}
	// We disqualify any name that has an IP address that is not a global
	// unicast address.
	for _, i := range addrs {
		if !i.IsGlobalUnicast() {
			return dnsBad
		}
		// Disallow RFC1918 address space too.
		if net10.Contains(i) || net172.Contains(i) || net192.Contains(i) || ipv6private.Contains(i) || ipv6siteloc.Contains(i) {
			return dnsBad
		}
	}
	return dnsGood
}

// ValidDomain returns whether or not the domain or host name exists in
// DNS as a valid target for mail. Unfortunately the Go net.Lookup*
// functions do not currently return useful Temporary() results for DNS
// server 'temporary failure' indications, so we can only give you yes/no
// results instead of a trinary yes / no / try-later indicator.
//
// The presence of any MX entry of '.' or 'localhost.' is taken as an
// indicator that this domain is not a valid mail delivery
// target. This is regardless of what other MX entries there may
// be. Similarly, a host with any IP addresses that are not valid
// global unicast addresses is disqualified even if it has other valid
// IP addresses.
//
// Note: RFC1918 addresses et al are not considered 'global' addresses
// by us. This may be arguable.
func ValidDomain(domain string) dnsResult {
	mxs, err := net.LookupMX(domain + ".")
	if err != nil && isTemporary(err) {
		return dnsTempfail
	}
	// No MX entry? Fall back to A record lookup.
	if err != nil {
		return checkIP(domain + ".")
	}

	// Check MX entries to see if they are valid. The whole thing is
	// valid the moment any one of them is; however, we can't short
	// circuit the check because we want to continue to check for
	// '.' et al in all MXes, even high preference ones.
	valid := dnsBad
	for _, m := range mxs {
		lc := strings.ToLower(m.Host)
		// Any MX entry of '.' or 'localhost.' means that this is
		// not a valid target; they've said 'do not send us email'.
		// *ANY* MX entry set this way will disqualify a host.
		if lc == "." || lc == "localhost." {
			return dnsBad
		}

		v := checkIP(m.Host)
		if v == dnsTempfail {
			valid = v
		}
		if valid == dnsBad && v == dnsGood {
			valid = dnsGood
		}
	}
	return valid
}
