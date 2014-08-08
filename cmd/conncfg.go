//
// Support different configurations, currently SSL keys and greeting banners,
// for incoming connections to different destinations.

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

type perDest struct {
	local string // local end of this connection

	// parameters:
	myname string
	certs  []tls.Certificate
}

type destMap []*perDest

func (d *destMap) find(nc net.Conn) *perDest {
	if d == nil {
		return nil
	}
	la := nc.LocalAddr()
	lip, _, _ := net.SplitHostPort(la.String())
	las := la.String()
	ip := net.ParseIP(lip)

	for _, de := range *d {
		if de.local == "*" || de.local == las {
			return de
		}
		if ip.Equal(net.ParseIP(de.local)) {
			return de
		}
		_, ipn, err := net.ParseCIDR(de.local)
		if err == nil && ipn.Contains(ip) {
			return de
		}
	}
	return nil
}

// Parse a file into a destMap
// Format of the file is:
//	ip-or-cidr	[hostname=<....>] [cert=<file> key=<file>]

func readConnFile(rdr *bufio.Reader) (*destMap, error) {
	var d destMap

	lnum := 0
	for {
		var host, cert, key string

		line, err := rdr.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		lnum++

		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		// ls has at least one entry because we're skipping blank
		// lines.
		ls := strings.Fields(line)
		if len(ls) > 4 {
			return nil, fmt.Errorf("too many fields in line %d", lnum)
		}
		// TODO: should check that ls[0] is a valid local name.
		pd := &perDest{local: ls[0]}

		// TODO: detect repeated keys
		for _, s := range ls[1:] {
			kv := strings.SplitN(s, "=", 2)
			if len(kv) != 2 {
				return nil, fmt.Errorf("field has no = in line %d", lnum)
			}
			switch kv[0] {
			case "hostname":
				host = kv[1]
			case "cert":
				cert = kv[1]
			case "key":
				key = kv[1]
			default:
				return nil, fmt.Errorf("unrecognized key '%s' in line %d", kv[0], lnum)
			}
		}

		// Set things from determined things.
		pd.myname = host
		switch {
		case cert != "" && key != "":
			cert, err := tls.LoadX509KeyPair(cert, key)
			if err != nil {
				return nil, fmt.Errorf("error loading TLS cert and key from line %d: %s", lnum, err)
			}
			pd.certs = []tls.Certificate{cert}
		case cert != "":
			return nil, fmt.Errorf("certificate without key on line %d", lnum)
		case key != "":
			return nil, fmt.Errorf("key without certificate on line %d", lnum)
		}
		d = append(d, pd)
	}
	return &d, nil
}

func loadConnFile(fname string) (*destMap, error) {
	fp, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	return readConnFile(bufio.NewReader(fp))
}
