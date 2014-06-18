/*
Sinksmtp is a sinkhole SMTP server. It accepts things and files them
away, or perhaps refuses things for you. It can log detailed transactions
if desired. Messages are received in all 8 bits, although we don't
advertise 8BITMIME.

usage: sinksmtp [options] [host]:port [[host]:port ...]

Options, sensibly organized:
	-M	Always send a rejection after email messages are received
		(post-DATA).  This rejection is 'fake' in that message
		details may be logged and messages may be saved, depending
		on other settings.

	-helo NAME
		Hostname to advertise in our greeting banner. If not
		set, we first try to look up the DNS name of the local
		IP of the connection, then just use the local 'IP:port'
		(which always exists). If DNS returns multiple names,
		we use the first.

	-S	Slow; send all server replies out to the network at a rate
		of one character every tenth of a second.

	-dncount NUM
		Start stalling a do-nothing client after this many
		connections in which it did not even EHLO successfully.
		Stalled clients get 4xx responses to everything and
		their SMTP sessions aren't logged. Only does something
		with -smtplog.
	-dndur DUR
		Both how long we stall a do-nothing client for before
		giving it a second chance and the time window over which
		we count do-nothing sessions.
	-minphase PHASE
		The minimum SMTP phase that a client must succeed at in
		order to not be considered a do-nothing client. One of
		helo/ehlo, from, to, data, message, or accepted. 'message'
		means that the client successfully sent us a message,
		even if we then reject it; 'accepted' is a sent message
		is accepted.

	-c FILE, -k FILE
		Provide TLS certificate and private key to enable TLS.
		Both files must be PEM encoded. Self-signed is fine.

	-l FILE
		Log one line per fully received message to this file,
		may be '-' for standard output.

	-smtplog FILE
		Log SMTP commands received and server output (and some
		additional info) to this file. May be '-' for stdout.

	-d DIR
		Save received messages to this directory; received files
		will be given probably-unique hash-based names. May be
		combined with -M, in which case messages will be logged
		then refused.  If there already is a file with the same
		hash-based name, we deliberately don't save over top of
		it (and don't generate any errors). You probably want
		-l too. The saved data includes message metadata.
	-save-hash TYPE
		Base the hash name on one of three things. See HASH
		NAMING later. Valid types are 'msg', 'full', and 'all'.
	-force-receive
		Accept email messages even without a -d (or a -M).

	-r FILE[,FILE2,...]
		Use FILE et al as control rules files. Rules in earlier
		files take priority over rules in later files.

A message's hash-based name normally includes everything saved in
the save file, including message metadata and thus including the
time the message was received (down to the second) and the message's
mostly unique log id. This will normally give all messages a different
hash even if the email is identical.

Discussion of control rules are beyond the scope of this
already-too-long documentation; see the RULES file. Explicitly set
command line options take priority over rules.

There are also some convenience options for common rule needs.
These are:
	-fromreject FILE
		Reject any MAIL FROM that matches something in this
		address list file.
	-toaccept FILE
		Only accept RCPT TO addresses that match something in
		this address list file (if it exists and is non-empty).
	-heloreject FILE
		Reject any EHLO/HELO name that matches something in in
		this host list file.

NOTE: the filenames here should not have funny characters in them
such as whitespace or commas; otherwise you'll probably get internal
errors or at least odd actions.

Address and hostname lists are reloaded from scratch every time we
start a new connection. It is valid for them to not exist or to have
no entries; this is the same as not specifying one at all (ie, we
accept everything). They are matched as all lower case. See RULES for
a discussion of what address and hostname patterns are.

Internally these options are compiled into control rules and
then checked before any rules in -r files. They are equivalent
to:
	reject from file:<whatever>
	reject not to file:<whatever>
	@from reject helo file:<whatever>

LOG ENTRIES AND SAVE FILES:

The format of this information is hopefully obvious.
In save files, everything up to and including the 'body' line is
message metadata (ie all '<name> ...' lines, with lower-case
<name>s); the actual message starts below 'body'. A 'tls' line
will only appear if the message was received over TLS. The cipher
numbers are in octal because that is all net/tls gives us and I
have not yet built a mapping. 'bodyhash ...' may not actually be
a hash for sufficiently mangled messages.
The ID that is printed in a number of places is composed of the
the daemon's PID plus a sequence number of connections that this
daemon has handled; this is to hopefully let you disentangle
multiple simultaneous connections in eg SMTP command logs.

'remote-dns' is the fully verified reverse DNS lookup results, ie
only reverse DNS names that include the remote IP as one of their
IP addresses in a forward lookup. 'remote-dns-nofwd' is reverse
DNS results that did not have a successful forward lookup;
'remote-dns-inconsist' is names that looked up but don't have the
remote IP listed as one of their IPs. Some or all may be missing
depending on DNS lookup results.

TLS: Go only supports SSLv3+ and we attempt to validate any client
certificate that clients present to us. Both can cause TLS setup to
fail (yes, there are apparently some MTAs that only support SSLv2).
When TLS setup fails we remember the client IP and don't offer TLS
to it if it reconnects within a certain amount of time (currently
72 hours).

HASH NAMING:

With -d DIR set up, sinksmtp saves messages under a hash name computed
for them. There are three possible hash names and 'all' is the default:

'msg' uses only the email contents themselves (the DATA) and doesn't
include metadata like MAIL FROM/RCPT TO/etc, which must be recovered
from the message log (-l). This requires -l to be set.

'full' adds metadata about the message to the hash (everything except
what appears on the 'id' line). If senders improperly resend messages
despite a 5xx rejection after the DATA is transmitted, this should
result in you saving only one copy of each fully unique message.

'all' adds all metadata, including the message ID and timestamp.
It will almost always be completely unique (well, assuming no hash
collisions in SHA1 and the sender doesn't send two copies from the
same source port in the same second).

Note that sinksmtp never exits. You must kill it by hand to shut
it down.

*/

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

// Suppress duplicate warning messages by running them all through
// a channel to a master, which can simply keep track of what the
// last message was.
var uniquer = make(chan string)

func warnonce(format string, elems ...interface{}) {
	s := fmt.Sprintf(format, elems...)
	uniquer <- s
}
func warnbackend() {
	var lastmsg string
	for {
		nmsg := <-uniquer
		if nmsg != lastmsg {
			fmt.Fprintf(os.Stderr, "sinksmtp: %s", nmsg)
			lastmsg = nmsg
		}
	}
}

// ----
// Read address lists in. This is done here because we call warnf()
// under some circumstances.
// TODO: fix that.
func readList(rdr *bufio.Reader) ([]string, error) {
	var a []string
	for {
		line, err := rdr.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return a, nil
			}
			return a, err
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}

		line = strings.ToLower(line)
		a = append(a, line)
	}
	// Cannot be reached; for loop has no breaks.
}

func loadList(fname string) []string {
	if fname == "" {
		return nil
	}
	fp, err := os.Open(fname)
	if err != nil {
		// An address list that is missing entirely is not an
		// error that we bother reporting.
		if !os.IsNotExist(err) {
			warnonce("error opening %s: %v\n", fname, err)
		}
		return nil
	}
	defer fp.Close()
	alist, err := readList(bufio.NewReader(fp))
	if err != nil {
		// We deliberately return a nil addrList on error instead
		// of a partial one.
		warnonce("Problem loading addr list %s: %v\n", fname, err)
		return nil
	}
	return alist
}

// ----
// Load a|the rule file. We assume filename is non-empty.
func loadRules(fname string) ([]*Rule, error) {
	fp, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer fp.Close()
	b, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil, err
	}
	rl, err := Parse(string(b))
	if err != nil {
		return nil, fmt.Errorf("rules parsing error %v", err)
	}
	return rl, nil
}

// our contract is that we always return either real rules or an error.
func accumRules(baserules []*Rule, fname string) ([]*Rule, error) {
	if fname == "" {
		return baserules, nil
	}
	rules, err := loadRules(fname)
	return append(baserules, rules...), err
}

// Accumulate the set of rules for this connection from our base rules
// (already pre-parsed) and rules loaded from our rules files, if any.
// If there are any errors in loading or parsing the rules files, we
// use the rules system itself to return a single rule that will defer
// everything.
func setupRules(baserules []*Rule) ([]*Rule, bool) {
	var rules []*Rule
	var rfile string
	var err error

	rules = baserules
	for _, rfile = range rulefiles {
		rules, err = accumRules(rules, rfile)
		if err != nil {
			break
		}
	}
	if err == nil {
		return rules, true
	}

	// Our rule is that if we're going to stall all activity, we're
	// going to write a warning message about it.
	// If the rules fail to load, we panic and stall everything via
	// the simple mechanism of generating a 'stall all' set of rules.
	warnonce("problem loading rules %s: %s\n", rfile, err)
	return stallall, false
}

// ----

// Support for IP blacklists. We have two.
//
// notls is a blacklist of IPs that have TLS problems when talking to
// us. If an IP is present and is more recent than tlsTimeout (3
// days), we don't advertise TLS to them even if we could.
//
// yakkers is a blacklist of people who have made too many connections
// to us that they didn't do anything meaningful with within a certain
// period of time. Implicitly this is yakTimeout. Yakkers get a 'stall
// all' timeout.

const tlsTimeout = time.Hour * 72

// Theoretically redundant in the face of flag settings.
var yakTimeout = time.Hour * 8
var yakCount = 5

type ipEnt struct {
	when  time.Time
	count int
}
type ipMap struct {
	sync.RWMutex
	ips map[string]*ipEnt
}

var notls = &ipMap{ips: make(map[string]*ipEnt)}
var yakkers = &ipMap{ips: make(map[string]*ipEnt)}

// We must take a TTL because we want to annul the count of existing
// but stale entries. Right now this only matters for yakkers, which
// is the only thing that cares about counts.
func (i *ipMap) Add(ip string, ttl time.Duration) {
	if ip == "" {
		return
	}
	i.Lock()
	t := i.ips[ip]
	switch {
	case t == nil:
		t = &ipEnt{}
		i.ips[ip] = t
	case time.Now().Sub(t.when) >= ttl:
		t.count = 0
	}
	t.count++
	t.when = time.Now()
	i.Unlock()
}

func (i *ipMap) Del(ip string) {
	i.Lock()
	delete(i.ips, ip)
	i.Unlock()
}
func (i *ipMap) Lookup(ip string, ttl time.Duration) (bool, int) {
	i.RLock()
	t := i.ips[ip]
	i.RUnlock()
	if t == nil {
		return false, 0
	}
	if time.Now().Sub(t.when) < ttl {
		return true, t.count
	}
	i.Del(ip)
	return false, 0
}

// This is used to log the SMTP commands et al for a given SMTP session.
// It encapsulates the prefix. Perhaps we could do this some other way,
// for example with a function closure, but PUNT for now.
// TODO: I'm convinced this is the wrong interface. See
//    http://utcc.utoronto.ca/~cks/space/blog/programming/GoLoggingWrongIdiom
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

	// we might as well create the buffer at the right size.
	buf := make([]byte, 0, len(b)+len(log.prefix))

	buf = append(buf, log.prefix...)
	buf = append(buf, b...)
	n, err = log.writer.Write(buf)
	if err == nil {
		err = log.writer.Flush()
	}
	return n, err
}

// ----
//
// SMTP transaction data accumulated for a single message. If multiple
// messages were delivered over the same Conn, some parts of this will
// be reused.
type smtpTransaction struct {
	raddr, laddr net.Addr
	rip          string
	lip          string
	rdns         *rDNSResults

	// these tracking fields are valid only after the relevant
	// phase/command has been accepted, ie they have the *accepted*
	// EHLO name, MAIL FROM, etc.
	heloname string
	from     string
	rcptto   []string

	data     string
	hash     string    // canonical hash of the data, currently SHA1
	bodyhash string    // canonical hash of the message body (no headers)
	when     time.Time // when the email message data was received.

	// Reflects the current state, so tlson false can convert to
	// tlson true over time. cipher is valid only if tlson is true.
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

func writeDNSList(writer io.Writer, pref string, dlist []string) {
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
	writeDNSList(writer, "remote-dns", trans.rdns.verified)
	writeDNSList(writer, "remote-dns-nofwd", trans.rdns.nofwd)
	writeDNSList(writer, "remote-dns-inconsist", trans.rdns.inconsist)
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
// Not all details covered by msgDetails() are reflected in the logfile,
// which is intended to be more terse.
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
	// O_CREATE|O_EXCL will fail if the file already exists, which
	// is okay with us.
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

// Decide what to do and then do it if it is a rejection or a tempfail.
// If given an id (and it is in the message handling phase) we call
// RejectData(). This is our convenience driver for the rules engine,
// Decide().
//
// Returns false if the message was accepted, true if decider() handled
// a rejection or tempfail.
func decider(ph Phase, evt smtpd.EventInfo, c *Context, convo *smtpd.Conn, id string) bool {
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
func process(cid int, nc net.Conn, certs []tls.Certificate, logf io.Writer, smtplog io.Writer, baserules []*Rule) {
	var evt smtpd.EventInfo
	var convo *smtpd.Conn
	var logger *smtpLogger
	var l2 io.Writer
	var gotsomewhere, stall bool

	defer nc.Close()

	trans := &smtpTransaction{}
	trans.raddr = nc.RemoteAddr()
	trans.laddr = nc.LocalAddr()
	prefix := fmt.Sprintf("%d/%d", os.Getpid(), cid)
	trans.rip, _, _ = net.SplitHostPort(trans.raddr.String())
	trans.lip, _, _ = net.SplitHostPort(trans.laddr.String())

	var c *Context
	// nit: in the presence of yakkers, we must know whether or not
	// the rules are good because bad rules turn *everyone* into
	// yakkers (since they prevent clients from successfully EHLO'ing).
	rules, rulesgood := setupRules(baserules)

	// A yakker is a client that is repeatedly connecting to us
	// without doing anything successfully. After a certain number
	// of attempts we turn them off. We only do this if we're logging
	// SMTP commands; if we're not logging, we don't care.
	// This is kind of a hack, but this code is for Chris and this is
	// what Chris cares about.
	hit, cnt := yakkers.Lookup(trans.rip, yakTimeout)
	if yakCount > 0 && hit && cnt >= yakCount && smtplog != nil {
		// nit: if the rules are bad and we're stalling anyways,
		// yakkers still have their SMTP transactions not logged.
		c = newContext(trans, stallall)
		stall = true
	} else {
		c = newContext(trans, rules)
	}
	//fmt.Printf("rules are:\n%+v\n", c.ruleset)

	if smtplog != nil && !stall {
		logger = &smtpLogger{}
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
	// stalled conversations are always slow, even if -S is not set.
	// TODO: make them even slower than this? I probably don't care.
	if goslow || stall {
		convo.AddDelay(time.Second / 10)
	}
	blocktls, _ := notls.Lookup(trans.rip, tlsTimeout)
	if len(certs) > 0 && !blocktls {
		var tlsc tls.Config
		tlsc.Certificates = certs
		tlsc.ClientAuth = tls.VerifyClientCertIfGiven
		tlsc.SessionTicketsDisabled = true
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
				if decider(pHelo, evt, c, convo, "") {
					continue
				}
				trans.heloname = evt.Arg
				trans.from = ""
				trans.data = ""
				trans.hash = ""
				trans.bodyhash = ""
				trans.rcptto = []string{}
				if minphase == "helo" {
					gotsomewhere = true
				}
			case smtpd.MAILFROM:
				if decider(pMfrom, evt, c, convo, "") {
					continue
				}
				trans.from = evt.Arg
				trans.data = ""
				trans.rcptto = []string{}
				if minphase == "from" {
					gotsomewhere = true
				}
			case smtpd.RCPTTO:
				if decider(pRto, evt, c, convo, "") {
					continue
				}
				trans.rcptto = append(trans.rcptto, evt.Arg)
				if minphase == "to" {
					gotsomewhere = true
				}
			case smtpd.DATA:
				if decider(pData, evt, c, convo, "") {
					continue
				}
				if minphase == "data" {
					gotsomewhere = true
				}
			}
		case smtpd.GOTDATA:
			// -minphase=message means 'message
			// successfully transmitted to us' as opposed
			// to 'message accepted'.
			if minphase == "message" {
				gotsomewhere = true
			}
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
				gotsomewhere = true
			case decider(pMessage, evt, c, convo, transid):
				// do nothing, already handled
			default:
				if minphase == "accepted" {
					gotsomewhere = true
				}
				convo.AcceptData(transid)
			}
		case smtpd.TLSERROR:
			// any TLS error means we'll avoid offering TLS
			// to this source IP for a while.
			notls.Add(trans.rip, tlsTimeout)
		}
		if evt.What == smtpd.DONE || evt.What == smtpd.ABORT {
			break
		}
	}
	// if the client did not issue any successful meaningful commands,
	// remember this. we squelch people who yak too long.
	// Once people are yakkers we don't count their continued failure
	// to do anything against them.
	// And we have to have good rules to start with because duh.
	switch {
	case !gotsomewhere && !stall && rulesgood && yakCount > 0:
		yakkers.Add(trans.rip, yakTimeout)
		// See if this transaction has pushed the client over the
		// edge to becoming a yakker. If so, report it to the SMTP
		// log.
		hit, cnt = yakkers.Lookup(trans.rip, yakTimeout)
		if hit && cnt >= yakCount && smtplog != nil {
			s := fmt.Sprintf("! %s added as a yakker at hit %d\n", trans.rip, cnt)
			logger.Write([]byte(s))
		}
	case gotsomewhere:
		yakkers.Del(trans.rip)
	}
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

// These settings are turned into rules.
var failgotdata bool
var fromreject string
var toaccept string
var heloreject string

// other settings.
var rulefiles []string

var goslow bool
var srvname string
var savedir string
var hashtype string
var minphase string

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

// Build the baseline rules that reflect the options.
func buildRules() []*Rule {
	var outbuf bytes.Buffer
	// We must split these rules because otherwise the to-has
	// requirement would defer this rule until RCPT TO even if
	// the MAIL FROM was bad.
	fmt.Fprintf(&outbuf, "reject from-has bad,route\n")
	fmt.Fprintf(&outbuf, "reject to-has bad,route\n")
	// We never accept blank EHLO/HELO, although smtpd will.
	fmt.Fprintf(&outbuf, "reject helo-has none\n")

	if failgotdata {
		fmt.Fprintf(&outbuf, "@message reject all\n")
	}

	// File based rejections.
	// We implicitly assume that there are no bad characters in the
	// filenames, because we currently don't have any way of quoting
	// things in the rule language. Moral: don't do that.
	// (Doing that will probably cause parsing to fail, so at least
	// we'll notice.)
	if fromreject != "" {
		fmt.Fprintf(&outbuf, "reject from file:%s\n", fromreject)
	}
	// It's not that we accept addresses in toaccept, it's that we
	// reject addresses that are not in it.
	if toaccept != "" {
		fmt.Fprintf(&outbuf, "reject not to file:%s\n", toaccept)
	}
	// standard heloreject behavior is to defer rejection until
	// MAIL FROM, because mail servers deal better with that.
	if heloreject != "" {
		fmt.Fprintf(&outbuf, "@from reject helo file:%s\n", heloreject)
	}

	// Parse the text into actual rules.
	s := outbuf.String()
	rules, err := Parse(s)
	if err != nil {
		// This should happen only when people give us bad
		// filenames for our 'file:' rules.
		die("error parsing autogenerated rules:\n\t%v\nrules:\n%s", err, s)
	}
	return rules
}

// Pre-generating the 'stall all' rule means that the main processing
// code can use it without having to check all the time if something
// went wrong while parsing it into actual rules.
var stallall []*Rule

func genStallRules() {
	var err error
	stallall, err = Parse("stall all")
	if err != nil || len(stallall) == 0 {
		// Should never happen.
		die("error parsing autogenerated nil rules:\n\t%v\n", err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\t%s [options] [host]:port [[host]:port ...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "\nOptions:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, noteStr)
}

var noteStr = `
See the manual for more comprehensive documentation.

Quick notes:
-helo's default value is either the hostname of the IP of the local
IP for the connection or 'IP:port' if the IP has no hostname.

The rejection from -M is applied after -d and/or -l, so a received
email will be saved and/or have its details logged before being
5xx'd to the client.

-save-hash's options are 'all' (all available information, almost
always unique names), 'full' (message plus most envelope metadata),
or 'msg' (actual received message only). Using 'msg' requires -l.
Setting -save-hash is meaningless without -d.

An empty or missing -fromreject, -heloreject, and/or -toaccept file
behaves as if the option hadn't been set. Files are checked and
reloaded for each new connection and thus can be changed on the fly.
If -toaccept is active, addresses that do not match something in
the file are rejected.

Control rule files are reloaded for each new connection. Any errors
in this process cause the connection to defer all commands with a
421 response (because sinksmtp can't safely do anything else).
`

func main() {
	var smtplogfile, logfile, rfiles string
	var certfile, keyfile string
	var force bool
	var certs []tls.Certificate

	// TODO: group these better. Handle these better? Something.
	flag.BoolVar(&failgotdata, "M", false, "reject all messages after they're fully received")
	flag.BoolVar(&goslow, "S", false, "send output to the network slowly (10 characters/sec)")
	flag.StringVar(&srvname, "helo", "", "server name for greeting banners")
	flag.StringVar(&smtplogfile, "smtplog", "", "log all SMTP conversations to here, '-' for stdout")
	flag.StringVar(&logfile, "l", "", "log summary info about received email to here, '-' for stdout")
	flag.StringVar(&savedir, "d", "", "directory to save received messages in")
	flag.BoolVar(&force, "force-receive", false, "force accepting email even without a -d directory")
	flag.StringVar(&hashtype, "save-hash", "all", "what to base the hash name of saved messages on")
	flag.StringVar(&certfile, "c", "", "TLS PEM certificate file; requires -k too")
	flag.StringVar(&keyfile, "k", "", "TLS PEM key file; requires -c too")
	flag.StringVar(&fromreject, "fromreject", "", "file of address patterns to reject in MAIL FROMs")
	flag.StringVar(&toaccept, "toaccept", "", "file of address patterns to accept in RCPT TOs")
	flag.StringVar(&heloreject, "heloreject", "", "file of hostname patterns to reject in EHLOs")
	flag.StringVar(&rfiles, "r", "", "comma separated list of files of control rules")
	flag.IntVar(&yakCount, "dncount", 0, "stall & don't log do-nothing clients after this many connections")
	flag.DurationVar(&yakTimeout, "dndur", time.Hour*8, "default do-nothing client timeout period and time window")
	flag.StringVar(&minphase, "minphase", "helo", "minimum successful phase to not be a do-nothing client")

	flag.Usage = usage

	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "%s: no arguments given about what to listen on\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "usage: %s [options] [host]:port [[host]:port ...]\n", os.Args[0])
		return
	}
	// This is theoretically too pessimistic in the face of a rules file,
	// but in that case you can give --force-receive. So.
	if savedir == "" && !(force || failgotdata) {
		die("I refuse to accept email without either a -d savedir or --force-receive\n")
	}
	if hashtype == "msg" && logfile == "" {
		// arguably we could rely on the SMTP log if there is one,
		// but no.
		die("-save-hash=msg requires a -l right now\n")
	}
	if !(hashtype == "msg" || hashtype == "full" || hashtype == "all") {
		die("bad option for -save-hash: '%s'. Only msg, full, and all are valid.\n", hashtype)
	}
	if yakCount > 0 && smtplogfile == "" {
		die("-dncount requires -smtplog")
	}
	if yakCount > 0 && yakTimeout < time.Second {
		die("-dndur is too small; must be at least one second")
	}

	switch {
	case certfile != "" && keyfile != "":
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			die("error loading TLS cert from %s & %s: %v\n", certfile, keyfile, err)
		}
		certs = []tls.Certificate{cert}

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

	// Save a lot of explosive problems by testing if we can actually
	// use the savedir right now, *before* we start doing stuff.
	if savedir != "" {
		tstfile := savedir + "/.wecanmake"
		fp, err := os.Create(tstfile)
		if err != nil {
			die("cannot create test file in savedir '%s': %v\n", savedir, err)
		}
		fp.Close()
		os.Remove(tstfile)
	}

	// Turn the rules file string into filenames and verify that they
	// are all there and readable.
	if rfiles != "" {
		rulefiles = strings.Split(rfiles, ",")
		for _, rf := range rulefiles {
			fp, err := os.Open(rf)
			if err != nil {
				die("cannot open rules file %s: %s\n", rf, err)
			}
			fp.Close()
		}
	}
	switch minphase {
	case "ehlo":
		// ehlo is a synonym for helo
		minphase = "helo"
	case "from", "to", "data", "message", "accepted":
		// it's okay
	default:
		die("invalid -minphase: must be helo/ehlo, from, to, data, message, or accepted")
	}

	baserules := buildRules()
	genStallRules()

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

	// start up our 'suppress duplicate warnings' backend goroutine
	go warnbackend()

	// Loop around getting new connections from our listeners and
	// handing them off to be processed. We insist on sitting in
	// the middle of the process so that we can maintain a global
	// connection count index, cid, for the purposes of creating
	// a semi-unique ID for each conversation.
	cid := 1
	for {
		nc := <-listenc
		go process(cid, nc, certs, logf, slogf, baserules)
		cid++
	}
}
