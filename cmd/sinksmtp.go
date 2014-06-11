// A sinkhole SMTP server.
// This accepts things and files them away, or perhaps refuses things for
// you. It can log detailed transactions if desired.
// Messages are received in all 8 bits, although we don't advertise
// 8BITMIME.
//
// usage: sinksmtp [options] host:port [host:port ...]
//
// Options, sensibly organized:
// -H, -F, -T, -D: reject everything after EHLO/HELO, MAIL FROM,
//                 RCPT TO, or DATA respectively. No email will be received.
// -M: always send a rejection after email messages are received (post-DATA).
//     This rejection is 'fake' in that message details may be logged and
//     messages may be saved, depending on other settings.
//
// -helo NAME: hostname to advertise in our greeting banner. If not set,
//             we first try to look up the DNS name of the local IP of
//             the connection, then just use the local 'IP:port' (which
//             always exists). If DNS returns multiple names, we use the
//             first.
// -S: slow; send all server replies out to the network at a rate of one
//     character every tenth of a second.
//
// -c FILE, -k FILE: provide TLS certificate and private key to enable TLS.
//                   Both files must be PEM encoded. Self-signed is fine.
//
// -l FILE: log one line per fully received message to this file, may be '-'
//          for standard output.
// -smtplog FILE: log SMTP commands received and server output (and some
//          additional info) to this file. May be '-' for stdout.
//
// -d DIR: save received messages to this directory; received files will
//         be given probably-unique hash-based names. May be combined
//         with -M, in which case messages will be logged then refused.
//         If there already is a file with the same hash-based name, we
//         don't save over top of it. You probably want -l too.
//         The saved data includes message metadata.
// -save-hash TYPE: Base the hash name on one of three things. See HASH
//         NAMING later. Valid types are 'msg', 'full', and 'all'.
// -force-receive: accept email messages even without a -d (or a -M).
//
// A message's hash-based name normally includes everything saved in
// the save file, including message metadata and thus including the
// time the message was received (down to the second) and the message's
// mostly unique log id. This will normally give all messages a different
// hash even if the email is identical.
//
// -fromreject FILE: reject any MAIL FROM that matches something
//         in this address list file.
// -toaccept FILE: only accept RCPT TO addresses that match something
//         in this address list file.
// -heloreject FILE: reject any EHLO/HELO name that matches something in
//         in this host list file.
// -dothelo: insist that every EHLO/HELO have a '.' or a ':', rejecting
//           obviously bogus ones.
//
// Address lists are reloaded from scratch every time we start a new
// connection. It is valid for them to not exist; this is the same as
// not specifying one at all (ie, we accept everything).
// Address lists are all matched as lower case. There are four sorts
// of entries: 'a@b' (matches full address), 'a@' (matches a local
// part at any domain), '@b' (matches any local part at the domain),
// '@.b' (matches any local part at the domain b or any subdomains of
// it). Note that our parsing of MAIL FROM/RCPT TO addresses is a bit
// naive.
// As a degenerate case, a simple '@' matches everything. Use this with
// care.
// Address lists may have comments (start with a '#') and blank lines.
// An empty address list (no actual entries) is treated as if it didn't
// exist.
//
// Host lists are like address lists except without the '@'. A name
// with no leading dots matches that name; a name with a starting '.'
// matches that name or any subdomains of it.
//
// LOG ENTRIES AND SAVE FILES:
// The format of this information is hopefully obvious.
// In save files, everything up to and including the 'body' line is
// message metadata (ie all '<name> ...' lines, with lower-case
// <name>s); the actual message starts below 'body'. A 'tls' line
// will only appear if the message was received over TLS. The cipher
// numbers are in octal because that is all net/tls gives us and I
// have not yet built a mapping. 'bodyhash ...' may not actually be
// a hash for sufficiently mangled messages.
// The ID that is printed in a number of places is composed of the
// the daemon's PID plus a sequence number of connections that this
// daemon has handled; this is to hopefully let you disentangle
// multiple simultaneous connections in eg SMTP command logs.
//
// 'remote-dns' is the fully verified reverse DNS lookup results, ie
// only reverse DNS names that include the remote IP as one of their
// IP addresses in a forward lookup. 'remote-dns-nofwd' is reverse
// DNS results that did not have a successful forward lookup;
// 'remote-dns-inconsist' is names that looked up but don't have the
// remote IP listed as one of their IPs. Some or all may be missing
// depending on DNS lookup results.
//
// TLS: Go only supports SSLv3+ and we attempt to validate any client
// certificate that clients present to us. Both can cause TLS setup to
// fail (yes, there are apparently some MTAs that only support SSLv2).
// When TLS setup fails we remember the client IP and don't offer TLS
// to it if it reconnects within a certain amount of time (currently
// 72 hours).
//
// HASH NAMING:
//
// With -d DIR set up, sinksmtp saves messages under a hash name computed
// for them. There are three possible hash names and 'all' is the default:
//
// 'msg' uses only the email contents themselves (the DATA) and doesn't
// include metadata like MAIL FROM/RCPT TO/etc, which must be recovered
// from the message log (-l). This requires -l to be set.
//
// 'full' adds metadata about the message to the hash (everything except
// what appears on the 'id' line). If senders improperly resend messages
// despite a 5xx rejection after the DATA is transmitted, this should
// result in you saving only one copy of each fully unique message.
//
// 'all' adds all metadata, including the message ID and timestamp.
// It will almost always be completely unique (well, assuming no hash
// collisions in SHA1 and the sender doesn't send two copies from the
// same source port in the same second).
//
// -----
//
// Note that sinksmtp never exits. You must kill it by hand to shut
// it down.
//
// TODO: needs lots of comments.
//
package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/siebenmann/smtpd"
	"io"
	"io/ioutil"
	"net"
	"net/mail"
	"os"
	"strings"
	"sync"
	"time"
)

// Our message/logging time format is time without the timezone.
const TimeNZ = "2006-01-02 15:04:05"

func warnf(format string, elems ...interface{}) {
	fmt.Fprintf(os.Stderr, "sinksmtp: "+format, elems...)
}

func die(format string, elems ...interface{}) {
	warnf(format, elems...)
	os.Exit(1)
}

// ----
// Address lists and address list lookup.
type addrList map[string]bool

func readList(rdr *bufio.Reader) (addrList, error) {
	var a = make(addrList)
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return a, nil
			} else {
				return a, err
			}
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		line = strings.ToLower(line)
		a[line] = true
	}
	// Cannot be reached; for loop has no breaks.
}

func loadList(fname string) addrList {
	if fname == "" {
		return nil
	}
	fp, err := os.Open(fname)
	if err != nil {
		// An address list that is missing entirely is not an
		// error that we bother reporting. We only report IO
		// errors reading the thing.
		return nil
	}
	defer fp.Close()
	alist, err := readList(bufio.NewReader(fp))
	if err != nil {
		// We deliberately return a nil addrList on error instead
		// of a partial one.
		warnf("Problem loading addr list %s: %v\n", fname, err)
		return nil
	}
	// If the list is completely empty after loading, we pretend
	// that it's nil. This may change someday but it seems safest
	// for now.
	if len(alist) == 0 {
		return nil
	} else {
		return alist
	}
}

// Iterate through a string of the form 'a.b.c', returning '.b.c', '.c',
// and then ''.
type sDotIter struct {
	s string
	p int // points to the dot.
}

func (s *sDotIter) Next() string {
	idx := strings.IndexByte(s.s[s.p+1:], '.')
	if idx == -1 {
		return ""
	}
	s.p += idx + 1
	return s.s[s.p:]
}

func inHostList(host string, alist addrList) bool {
	host = strings.ToLower(host)
	if alist[host] || alist["."+host] {
		return true
	}
	si := &sDotIter{s: host}
	for h := si.Next(); h != ""; h = si.Next() {
		if alist[h] {
			return true
		}
	}
	return false
}

// def is what to return if the addrlist is nil.
func inAddrList(addr string, alist addrList, def bool) bool {
	var ts string
	if alist == nil {
		return def
	}
	addr = strings.ToLower(addr)
	idx := strings.IndexByte(addr, '@')
	if idx == -1 {
		return alist[addr]
	}
	local := addr[:idx+1]
	domain := addr[idx:]
	if alist[addr] || alist[local] || alist[domain] {
		return true
	}
	// Look for partial domain match
	// Note that domain starts with an @, so we must skip it when
	// setting things up.
	// trivial root: a bare '@' matches everything.
	// TODO: do I want this? Allowing it makes this code simpler,
	// though.
	si := &sDotIter{s: domain[1:]}
	for ts != "@" {
		ts = "@" + si.Next()
		if alist[ts] {
			return true
		}
	}
	// base case: we have '@dom.ain' and want to match a '@.dom.ain' entry
	ts = "@." + domain[1:]
	return alist[ts]
}

// ----
func loadRules(fname string) []*Rule {
	if fname == "" {
		return nil
	}
	fp, err := os.Open(fname)
	if err != nil {
		return nil
	}
	defer fp.Close()
	b, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil
	}
	rl, e := Parse(string(b))
	if e != nil {
		warnf("rules parsing error %s\n", *e)
		return nil
	}
	return rl
}

// ----

// This is a blacklist of IPs that have TLS problems when talking to
// us. If an IP is present and is more recent than tlsTimeout (3 days),
// we don't advertise TLS to them even if we could.
const tlsTimeout = time.Hour * 72

var ipmap = struct {
	sync.RWMutex
	ips map[string]time.Time
}{ips: make(map[string]time.Time)}

// add an IP to the IP map, with the current time
func ipAdd(ip string) {
	if ip == "" {
		return
	}
	ipmap.Lock()
	ipmap.ips[ip] = time.Now()
	ipmap.Unlock()
}

// delete an IP from the map if present
func ipDel(ip string) {
	ipmap.Lock()
	delete(ipmap.ips, ip)
	ipmap.Unlock()
}

// is an IP present (and non-stale) in the map?
func ipPresent(ip string) bool {
	ipmap.RLock()
	t := ipmap.ips[ip]
	ipmap.RUnlock()
	if t.IsZero() {
		return false
	}
	if time.Now().Sub(t) < tlsTimeout {
		return true
	} else {
		// Entry is stale, purge.
		ipDel(ip)
		return false
	}
}

// This is used to log the SMTP commands et al for a given SMTP session.
// It encapsulates the prefix. Perhaps we could do this some other way,
// for example with a function closure, but PUNT for now.
type smtpLogger struct {
	prefix []byte
	writer *bufio.Writer
}

func (log *smtpLogger) Write(b []byte) (n int, err error) {
	// MY HEAD HURTS. WHY DOES THIS HAPPEN.
	// ... long story involving implicit casts to interfaces.
	// This safety code is disabled because I want a crash if I screw
	// this up at a higher level. This may be a mistake.
	//if log == nil {
	//	return
	//}

	var buf []byte
	buf = append(buf, log.prefix...)
	buf = append(buf, b...)
	n, err = log.writer.Write(buf)
	if err == nil {
		err = log.writer.Flush()
	}
	return n, err
}

// SMTP transaction data accumulated for a single message. If multiple
// messages were delivered over the same Conn, some parts of this will
// be reused.
type smtpTransaction struct {
	raddr, laddr net.Addr
	heloname     string
	from         string
	rcptto       []string

	data     string
	hash     string    // canonical hash of the data, currently SHA1
	bodyhash string    // canonical hash of the message body (no headers)
	when     time.Time // when the email message data was received.

	rip  string
	rdns *rDnsResults

	tlson  bool
	cipher uint16
}

// returns overall hash and body-of-message hash. The latter may not
// exist if the message is mangled, eg no actual body.
func genHash(b []byte) string {
	h := sha1.New()
	h.Write(b)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func getHashes(trans *smtpTransaction) (string, string) {
	var hash, bodyhash string

	hash = genHash([]byte(trans.data))

	msg, err := mail.ReadMessage(strings.NewReader(trans.data))
	if err != nil {
		return hash, "<cannot-parse-message>"
	}
	body, err := ioutil.ReadAll(msg.Body)
	if err != nil {
		return hash, "<cannot-read-body?>"
	}
	bodyhash = genHash(body)
	return hash, bodyhash
}

func writeDnsList(writer io.Writer, pref string, dlist []string) {
	if len(dlist) == 0 {
		return
	}
	fmt.Fprintf(writer, pref)
	for _, e := range dlist {
		fmt.Fprintf(writer, " %s", e)
	}
	fmt.Fprintf(writer, "\n")
}

// return a block of bytes that records the message details,
// including the actual message itself. We also return a hash of what
// we consider the constant data about this message, which included
// envelope metadata and the source IP and its DNS information.
func msgDetails(prefix string, trans *smtpTransaction) ([]byte, string) {
	var outbuf, outbuf2 bytes.Buffer

	fwrite := bufio.NewWriter(&outbuf)
	fmt.Fprintf(fwrite, "id %s %v %s\n", prefix, trans.raddr,
		trans.when.Format(TimeNZ))
	writer := bufio.NewWriter(&outbuf2)
	rmsg := trans.rip
	if rmsg == "" {
		rmsg = trans.raddr.String()
	}
	fmt.Fprintf(writer, "remote %s to %v with helo '%s'\n", rmsg,
		trans.laddr, trans.heloname)
	writeDnsList(writer, "remote-dns", trans.rdns.verified)
	writeDnsList(writer, "remote-dns-nofwd", trans.rdns.nofwd)
	writeDnsList(writer, "remote-dns-inconsist", trans.rdns.inconsist)
	if trans.tlson {
		fmt.Fprintf(writer, "tls on cipher 0x%04x", trans.cipher)
		if cn := cipherNames[trans.cipher]; cn != "" {
			fmt.Fprintf(writer, " name %s", cn)
		}
		fmt.Fprintf(writer, "\n")
	}
	fmt.Fprintf(writer, "from <%s>\n", trans.from)
	for _, a := range trans.rcptto {
		fmt.Fprintf(writer, "to <%s>\n", a)
	}
	fmt.Fprintf(writer, "hash %s bytes %d\n", trans.hash, len(trans.data))
	fmt.Fprintf(writer, "bodyhash %s\n", trans.bodyhash)
	fmt.Fprintf(writer, "body\n%s", trans.data)
	writer.Flush()
	metahash := genHash(outbuf2.Bytes())
	fwrite.Write(outbuf2.Bytes())
	fwrite.Flush()
	return outbuf.Bytes(), metahash
}

// Log details about the message to the logfile.
func logMessage(prefix string, trans *smtpTransaction, logf io.Writer) {
	if logf == nil {
		return
	}
	var outbuf bytes.Buffer
	writer := bufio.NewWriter(&outbuf)
	fmt.Fprintf(writer, "%s [%s] from %v / ",
		trans.when.Format(TimeNZ), prefix,
		trans.raddr)
	fmt.Fprintf(writer, "<%s> to", trans.from)
	for _, a := range trans.rcptto {
		fmt.Fprintf(writer, " <%s>", a)
	}
	fmt.Fprintf(writer, ": message %d bytes hash %s body %s | local %v helo '%s'",
		len(trans.data), trans.hash, trans.bodyhash, trans.laddr,
		trans.heloname)
	if trans.tlson {
		fmt.Fprintf(writer, " tls:cipher 0x%04x", trans.cipher)
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
	logf.Write(outbuf.Bytes())
}

// Having received a message, do everything to it that we want to.
// Here we log the message reception and possibly save it.
func handleMessage(prefix string, trans *smtpTransaction, logf io.Writer) (string, error) {
	var hash string
	logMessage(prefix, trans, logf)
	if savedir == "" {
		return trans.hash, nil
	}
	m, mhash := msgDetails(prefix, trans)
	// There are three possible hashes for message naming:
	//
	// 'msg' uses only the DATA (actual email) and counts on the
	// transaction log to recover metadata.
	//
	// 'full' adds all metadata except the ID line and the sender
	// port; this should squelch duplicates that emerge from
	// things that resend after a rejected DATA transaction.
	//
	// 'all' adds even the ID line and the sender port, which is
	// very likely to be completely unique for every message (a
	// sender would have to reuse the same source port for a
	// message received within a second).
	//
	// There is no option to save based on the body hash alone,
	// because that would lose data unless we saved the message
	// headers separately and no let's not get that complicated.
	switch hashtype {
	case "msg":
		hash = trans.hash
	case "full":
		hash = mhash
	case "all":
		hash = genHash(m)
	default:
		panic(fmt.Sprintf("unhandled hashtype '%s'", hashtype))
	}

	tgt := savedir + "/" + hash
	fp, err := os.OpenFile(tgt, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err == nil {
		fp.Write(m)
		fp.Close()
	} else {
		if !os.IsExist(err) {
			warnf("error writing message file: %v\n", err)
		} else {
			err = nil
		}
	}
	return hash, err
}

// We could do a better job of validating the EHLO if we wanted to,
// eg looking for properly formed IPv4 and IPv6 literal addresses, but
// no. This is a quick hack to get rid of obviously terrible things,
// basically the people who EHLO with 'randomnodotsstring', because
// they tend to be completely uninteresting spam.
func acceptHelo(helo string) bool {
	if !dothelo {
		return true
	}
	idx := strings.IndexByte(helo, '.')
	idx2 := strings.IndexByte(helo, ':') // for IPv6 literal addresses
	if idx != -1 || idx2 != -1 {
		return true
	} else {
		return false
	}
}

// Cannot be a route address (starts with '@') or terribly mangled (starts
// with '<'). Must have a non-empty local part and domain part.
// smtpd.go's addr_valid() has already checked that there is an '@' and
// a '.' after the @.
func isGoodAddress(addr string) bool {
	if addr == "" {
		return true
	}
	// We reject route addresses, and also people who send us
	// 'MAIL FROM:<<....>>' (yes, they do this sometimes).
	if addr[0] == '<' || addr[0] == '@' {
		return false
	}
	// axiomatically '@' is not the first character so there is a
	// non-null local part.
	return true
}

func gronk(ph Phase, evt smtpd.EventInfo, c *Context, convo *smtpd.Conn, id string) bool {
	if c == nil {
		return false
	}
	res := Decide(ph, evt, c)
	if res == aNoresult || res == aAccept {
		return false
	}
	switch res {
	case aReject:
		if id != "" && ph == pMessage {
			convo.RejectData(id)
		} else {
			convo.Reject()
		}
	case aStall:
		convo.Tempfail()
	default:
		panic("impossible res")
	}
	return true
}

// Process a single connection.
// We take tlsc as a value instead of a literal because we are going to
// change it (to set tlsc.ServerName). This causes 'go vet' to complain
// that we are copying a lock (in an internal field in tls.Config). This
// is true but it's also the case that we're passing an unused tls.Config
// in, so the lock should be at its zero value. Right now I decline to make
// the code more elaborate to pacify 'go vet'.
func process(cid int, nc net.Conn, tlsc tls.Config, logf io.Writer, smtplog io.Writer) {
	var evt smtpd.EventInfo
	var convo *smtpd.Conn
	var l2 io.Writer
	var poisoned bool

	trans := &smtpTransaction{}
	trans.raddr = nc.RemoteAddr()
	trans.laddr = nc.LocalAddr()
	prefix := fmt.Sprintf("%d/%d", os.Getpid(), cid)
	trans.rip, _, _ = net.SplitHostPort(nc.RemoteAddr().String())

	fromrej := loadList(fromreject)
	toacpt := loadList(toaccept)
	helorej := loadList(heloreject)

	var c *Context
	rules := loadRules(rulesfile)
	if rules != nil && len(rules) > 0 {
		c = &Context{trans: trans, ruleset: rules}
	}

	if smtplog != nil {
		logger := &smtpLogger{}
		logger.prefix = []byte(prefix)
		logger.writer = bufio.NewWriterSize(smtplog, 8*1024)
		l2 = logger
	}

	sname := trans.laddr.String()
	if srvname != "" {
		sname = srvname
	} else {
		lip, _, _ := net.SplitHostPort(sname)
		// we don't do a verified lookup of the local IP address
		// because it's theoretically under your control, so if
		// you want to forge stuff that's up to you.
		nlst, err := net.LookupAddr(lip)
		if err == nil && len(nlst) > 0 {
			sname = nlst[0]
			if sname[len(sname)-1] == '.' {
				sname = sname[:len(sname)-1]
			}
		}
	}
	convo = smtpd.NewConn(nc, sname, l2)
	convo.SayTime = true
	if goslow {
		convo.AddDelay(time.Second / 10)
	}
	if len(tlsc.Certificates) > 0 && !ipPresent(trans.rip) {
		tlsc.ServerName = sname
		convo.AddTLS(&tlsc)
	}

	// Yes, we do rDNS lookup before our initial greeting banner and
	// thus can pause a bit here. Clients will cope, or at least we
	// don't care if impatient ones don't.
	trans.rdns, _ = LookupAddrVerified(trans.rip)

	// Main transaction loop. We gather up email messages as they come
	// in, possibly failing various operations as we're told to.
	for {
		evt = convo.Next()
		switch evt.What {
		case smtpd.COMMAND:
			switch evt.Cmd {
			case smtpd.EHLO, smtpd.HELO:
				if failhelo || !acceptHelo(evt.Arg) {
					convo.Reject()
					continue
				}
				// If a host is listed in the no-EHLO list,
				// we don't immediately reject it; historically
				// some MTAs have not liked that. We defer
				// rejection until MAIL FROM.
				// Note that poisoning is permanent; once
				// you EHLO with a bad name, it cannot be
				// reset.
				if inHostList(evt.Arg, helorej) {
					poisoned = true
				}
				if gronk(pHelo, evt, c, convo, "") {
					continue
				}
				trans.heloname = evt.Arg
				trans.from = ""
				trans.data = ""
				trans.hash = ""
				trans.bodyhash = ""
				trans.rcptto = []string{}
			case smtpd.MAILFROM:
				if failmail || !isGoodAddress(evt.Arg) {
					convo.Reject()
					continue
				}
				if evt.Arg != "" && inAddrList(evt.Arg, fromrej, false) {
					convo.Reject()
					continue
				}
				// Trivial root: we accept MAIL FROM:<>
				// even from poisoned hosts and defer rejection
				// to RCPT TO time. This is more RFC compliant
				// and therefor less likely to cause MTAs to
				// choke.
				if evt.Arg != "" && poisoned {
					convo.Reject()
					continue
				}
				if gronk(pMfrom, evt, c, convo, "") {
					continue
				}
				trans.from = evt.Arg
				trans.data = ""
				trans.rcptto = []string{}
			case smtpd.RCPTTO:
				if failrcpt || !isGoodAddress(evt.Arg) || poisoned {
					convo.Reject()
					continue
				}
				if !inAddrList(evt.Arg, toacpt, true) {
					convo.Reject()
					continue
				}
				if gronk(pRto, evt, c, convo, "") {
					continue
				}
				trans.rcptto = append(trans.rcptto, evt.Arg)
			case smtpd.DATA:
				if faildata {
					convo.Reject()
				}
				gronk(pData, evt, c, convo, "")
			}
		case smtpd.GOTDATA:
			// message rejection is deferred until after logging
			// et al.
			trans.data = evt.Arg
			trans.when = time.Now()
			trans.tlson = convo.TLSOn
			trans.cipher = convo.TLSCipher
			trans.hash, trans.bodyhash = getHashes(trans)
			transid, err := handleMessage(prefix, trans, logf)
			// errors when handling a message always force
			// a tempfail regardless of how we're
			// configured.
			switch {
			case err != nil:
				convo.Tempfail()
			case failgotdata:
				convo.RejectData(transid)
			case gronk(pMessage, evt, c, convo, transid):
				// do nothing, already gronkd
			default:
				convo.AcceptData(transid)
			}
		case smtpd.TLSERROR:
			ipAdd(trans.rip)
		}
		if evt.What == smtpd.DONE || evt.What == smtpd.ABORT {
			break
		}
	}
	nc.Close()
}

// Listen for new connections on a net.Listener, send the result to
// the master.
func listener(conn net.Listener, listenc chan net.Conn) {
	for {
		nc, err := conn.Accept()
		if err == nil {
			listenc <- nc
		}
	}
}

// Our absurd collection of global settings.
var failhelo bool
var failmail bool
var failrcpt bool
var faildata bool
var failgotdata bool
var goslow bool
var srvname string
var savedir string
var hashtype string
var dothelo bool
var fromreject string
var toaccept string
var heloreject string
var rulesfile string

func openlogfile(fname string) (outf io.Writer, err error) {
	if fname == "" {
		return nil, nil
	}
	if fname == "-" {
		return os.Stdout, nil
	}
	return os.OpenFile(fname,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

func main() {
	var smtplogfile, logfile string
	var certfile, keyfile string
	var force bool
	var tlsConfig tls.Config

	flag.BoolVar(&failhelo, "H", false, "reject all HELO/EHLOs")
	flag.BoolVar(&failmail, "F", false, "reject all MAIL FROMs")
	flag.BoolVar(&failrcpt, "T", false, "reject all RCPT TOs")
	flag.BoolVar(&faildata, "D", false, "reject all DATA commands")
	flag.BoolVar(&failgotdata, "M", false, "reject all messages after they're fully received. This rejection is 'fake', as messages may still be logged and/or saved if either is configured.")
	flag.BoolVar(&goslow, "S", false, "send output to the network at one character every tenth of a second")
	flag.StringVar(&srvname, "helo", "", "server name to advertise in greeting banners, defaults to local IP:port of connection")
	flag.StringVar(&smtplogfile, "smtplog", "", "filename for SMTP conversation logs, '-' means standard output, no default")
	flag.StringVar(&logfile, "l", "", "filename of the transaction log, no default")
	flag.StringVar(&savedir, "d", "", "directory to save received messages in")
	flag.BoolVar(&force, "force-receive", false, "force accepting email even without a savedir")
	flag.StringVar(&hashtype, "save-hash", "all", "hash name for saved messages is based on the actual message ('msg'), message plus most envelope metadata ('full'), or all available information including timestamp ('all')")
	flag.StringVar(&certfile, "c", "", "TLS PEM certificate file")
	flag.StringVar(&keyfile, "k", "", "TLS PEM key file")
	flag.BoolVar(&dothelo, "dothelo", false, "require EHLO/HELO to contain a dot or a :")
	flag.StringVar(&fromreject, "fromreject", "", "if set, filename of address patterns to reject in MAIL FROMs")
	flag.StringVar(&toaccept, "toaccept", "", "if set, filename of address patterns to accept in RCPT TOs (all others will be rejected if there are any entries in the file)")
	flag.StringVar(&heloreject, "heloreject", "", "if set, filename of address patterns to reject in EHLO/HELO names")
	flag.StringVar(&rulesfile, "r", "", "if set, filename of a set of control rules")

	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: sinksmtp [options] host:port [host:port ...]")
		return
	}
	if savedir == "" && !(force || failhelo || failmail || failrcpt || faildata || failgotdata) {
		die("I refuse to accept email without either a -d savedir or --force-receive\n")
	}
	if hashtype == "msg" && logfile == "" {
		// arguably we could rely on the SMTP log if there is one,
		// but no.
		die("-save-hash=msg requires a logfile right now\n")
	}
	if !(hashtype == "msg" || hashtype == "full" || hashtype == "all") {
		die("bad value for -save-hash: '%s'. Only msg, full, and all are valid.\n", hashtype)
	}

	switch {
	case certfile != "" && keyfile != "":
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			die("error loading TLS cert from %s & %s: %v\n", certfile, keyfile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.SessionTicketsDisabled = true

	case certfile != "":
		die("certfile specified without keyfile\n")
	case keyfile != "":
		die("keyfile specified without certfile\n")
	}

	slogf, err := openlogfile(smtplogfile)
	if err != nil {
		die("error opening SMTP log file '%s': %v\n", smtplogfile, err)
	}
	logf, err := openlogfile(logfile)
	if err != nil {
		die("error opening logfile '%s': %v\n", logfile, err)
	}

	if savedir != "" {
		tstfile := savedir + "/.wecanmake"
		fp, err := os.Create(tstfile)
		if err != nil {
			die("cannot create test file in savedir '%s': %v\n", savedir, err)
		}
		fp.Close()
		os.Remove(tstfile)
	}

	// Set up a pool of listeners, one per address that we're supposed
	// to be listening on. These are goroutines that multiplex back to
	// us on listenc.
	listenc := make(chan net.Conn)
	for i := 0; i < flag.NArg(); i++ {
		conn, err := net.Listen("tcp", flag.Arg(i))
		if err != nil {
			die("error listening to tcp!%s: %s\n", flag.Arg(i), err)
		}
		go listener(conn, listenc)
	}

	// Loop around getting new connections from our listeners and
	// handing them off to be processed. We insist on sitting in
	// the middle of the process so that we can maintain a global
	// connection count index, cid, for the purposes of creating
	// a semi-unique ID for each conversation.
	cid := 1
	for {
		nc := <-listenc
		go process(cid, nc, tlsConfig, logf, slogf)
		cid += 1
	}
}
