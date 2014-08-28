// For sinksmtp usage and other documentation, see doc.go
// godoc . will show it.

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
	"net/http"
	_ "net/http/pprof"
	"net/mail"
	"os"
	"runtime"
	"sort"
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

// TODO: work out a way to clear this so that a sequence of
// parse error -> everything is clear -> same parse error again
// results in the error being printed again.
func warnbackend() {
	var lastmsg string
	for {
		nmsg := <-uniquer
		if nmsg != lastmsg {
			if nmsg != "" {
				fmt.Fprintf(os.Stderr, "sinksmtp: %s", nmsg)
			}
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

	savedir string // directory to save message to

	// Reflects the current state, so tlson false can convert to
	// tlson true over time. cipher is valid only if tlson is true.
	tlson      bool
	cipher     uint16
	servername string

	// Make our logger accessible in decider() as a hack.
	log     *smtpLogger
	lastmsg string
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
		if trans.servername != "" {
			fmt.Fprintf(writer, " server-name '%s'", trans.servername)
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
	if trans.savedir == "" {
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

	tgt := trans.savedir + "/" + hash
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

// Given a SBL hit on a remote IP, try to give us what SBL records were hit.
func getSBLHits(t *smtpTransaction) []string {
	var sbls []string
	// since we know this hit, we can omit a lot of checks.
	s := strings.Split(t.rip, ".")
	ln := fmt.Sprintf("%s.%s.%s.%s.sbl.spamhaus.org.", s[3], s[2], s[1], s[0])
	txts, err := net.LookupTXT(ln)
	if err != nil {
		return sbls
	}
	for _, txt := range txts {
		idx := strings.LastIndex(txt, "/")
		if idx == -1 || idx == len(txt)-1 {
			continue
		}
		sbls = append(sbls, txt[idx+1:])
	}
	sort.Strings(sbls)
	return sbls
}

// As a hack, log DNSBL hits if any. These hits may not have
// determined the results but there you go.
// This is a hack but I want to capture this information somehow.
func logDnsbls(c *Context) {
	if len(c.dnsblhit) == 0 || c.trans.log == nil {
		return
	}

	sort.Strings(c.dnsblhit)
	lmsg := fmt.Sprintf("! dnsbl hit: %s\n",
		strings.Join(c.dnsblhit, " "))
	if lmsg == c.trans.lastmsg {
		return
	}
	c.trans.log.Write([]byte(lmsg))
	c.trans.lastmsg = lmsg

	// Special bonus feature: log actual SBL entries.
	for i := range c.dnsblhit {
		if c.dnsblhit[i] == "sbl.spamhaus.org." {
			sbls := getSBLHits(c.trans)
			if len(sbls) > 0 {
				lmsg = fmt.Sprintf("! SBL records: %s\n",
					strings.Join(sbls, " "))
				c.trans.log.Write([]byte(lmsg))
			}
		}
	}
}

// trivial but I care about these messages, neurotic though it may be.
func pluralRecips(c *Context) string {
	if len(c.trans.rcptto) > 1 {
		return "those addresses"
	}
	return "that address"
}

func doAccept(convo *smtpd.Conn, c *Context, transid string) {
	msg := c.withprops["message"]
	switch {
	case msg != "":
		if transid != "" {
			msg += "\nAccepted with ID " + transid
		}
		convo.AcceptMsg(msg)
	case transid != "":
		convo.AcceptData(transid)
	default:
		convo.Accept()
	}
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

	logDnsbls(c)
	// The moment a rule sets a savedir, it becomes sticky.
	// This lets you select a savedir based on eg from matching
	// instead of having to do games later.
	if sd := c.withprops["savedir"]; sd != "" {
		c.trans.savedir = sd
	}
	// rule notes are deliberately logged every time they hit.
	// this may be a mistake given EHLO retrying as HELO, but
	// I'll see.
	if note := c.withprops["note"]; note != "" {
		c.trans.log.Write([]byte(fmt.Sprintf("! rule note: %s\n", note)))
	}
	// Disable TLS if desired, or just disable asking for client certs.
	switch c.withprops["tls-opt"] {
	case "off":
		convo.Config.TLSConfig = nil
	case "no-client":
		// 'tls-opt no-client' without certificates should not
		// crash.
		if convo.Config.TLSConfig != nil {
			convo.Config.TLSConfig.ClientAuth = tls.NoClientCert
		}
	}

	if res == aNoresult || res == aAccept {
		return false
	}

	if ph == pConnect {
		// TODO: have some way to stall or reject connections
		// in smtpd. Or should that be handled outside of it?
		// Right now a reject result means 'drop', stall will
		// implicitly cause us to go on.
		return res == aReject
	}

	msg := c.withprops["message"]
	switch res {
	case aReject:
		// This is kind of a hack.
		// We assume that 'id' is only set when we should report it,
		// which is kind of safe.
		if msg != "" {
			if id != "" {
				msg += "\nRejected with ID " + id
			}
			convo.RejectMsg(msg)
			return true
		}
		// Default messages are kind of intricate.
		switch {
		case id != "" && ph == pMessage:
			convo.RejectMsg("We do not consent to you emailing %s\nRejected with ID %s", pluralRecips(c), id)
		case ph == pMessage || ph == pData:
			convo.RejectMsg("We do not consent to you emailing %s", pluralRecips(c))
		case ph == pRto:
			convo.RejectMsg("We do not consent to you emailing that address")
		default:
			convo.Reject()
		}
	case aStall:
		if msg != "" {
			convo.TempfailMsg(msg)
		} else {
			convo.Tempfail()
		}
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
	var gotsomewhere, stall, sesscounts bool
	var cfg smtpd.Config

	defer nc.Close()

	trans := &smtpTransaction{}
	trans.savedir = savedir
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
	// sesscounts is true if this session should count for being a
	// 'bad' session if we don't get far enough. Sessions with TLS
	// errors don't count, as do sessions with bad rules or sessions
	// where yakCount == 0.
	sesscounts = rulesgood && yakCount > 0
	hit, cnt := yakkers.Lookup(trans.rip, yakTimeout)
	if yakCount > 0 && hit && cnt >= yakCount && smtplog != nil {
		// nit: if the rules are bad and we're stalling anyways,
		// yakkers still have their SMTP transactions not logged.
		c = newContext(trans, stallall)
		stall = true
		sesscounts = false
	} else {
		c = newContext(trans, rules)
	}
	//fmt.Printf("rules are:\n%+v\n", c.ruleset)

	if smtplog != nil && !stall {
		logger = &smtpLogger{}
		logger.prefix = []byte(prefix)
		logger.writer = bufio.NewWriterSize(smtplog, 8*1024)
		trans.log = logger
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

	if connfile != "" {
		dm, err := loadConnFile(connfile)
		if err != nil {
			warnf("error loading per-connection rules '%s': %s\n", connfile, err)
		}
		// dm.find() explicitly works even on nil dm, so we don't
		// need to guard it.
		if pd := dm.find(nc); pd != nil {
			if pd.myname != "" {
				sname = pd.myname
			}
			certs = pd.certs
		}
	}

	cfg.LocalName = sname
	cfg.SayTime = true
	cfg.SftName = "sinksmtp"
	cfg.Announce = "This server does not deliver email."

	// stalled conversations are always slow, even if -S is not set.
	// TODO: make them even slower than this? I probably don't care.
	if goslow || stall {
		cfg.Delay = time.Second / 10
	}

	// Don't offer TLS to hosts that have too many TLS failures.
	// We give hosts *two* tries at setting up TLS because some
	// hosts start by offering SSLv2, which is an instant-fail,
	// even if they support stuff that we do. We hope that their
	// SSLv2 failure will cause them to try again in another
	// connection with TLS only.
	// See https://code.google.com/p/go/issues/detail?id=3930
	blocktls, blcount := notls.Lookup(trans.rip, tlsTimeout)
	if len(certs) > 0 && !(blocktls && blcount >= 2) {
		var tlsc tls.Config
		tlsc.Certificates = certs
		// if there is already one TLS failure for this host,
		// it might be because of a bad client certificate.
		// so on the second time around we don't ask for one.
		// (More precisely we only ask for a client cert if
		// there are no failures so far.)
		if blcount == 0 {
			tlsc.ClientAuth = tls.VerifyClientCertIfGiven
		}
		tlsc.SessionTicketsDisabled = true
		tlsc.ServerName = sname
		tlsc.BuildNameToCertificate()
		cfg.TLSConfig = &tlsc
	}

	// With everything set up we can now create the connection.
	convo = smtpd.NewConn(nc, cfg, l2)

	// Yes, we do rDNS lookup before our initial greeting banner and
	// thus can pause a bit here. Clients will cope, or at least we
	// don't care if impatient ones don't.
	trans.rdns, _ = LookupAddrVerified(trans.rip)

	// Check for an immediate result on the initial connection. This
	// may disable TLS or refuse things immediately.
	if decider(pConnect, evt, c, convo, "") {
		// TODO: somehow write a message and maybe log it.
		// this probably needs smtpd.go cooperation.
		// Right now we just close abruptly.
		if smtplog != nil && !stall {
			s := fmt.Sprintf("! %s dropped on connect due to rule at %s\n", trans.rip, time.Now().Format(smtpd.TimeFmt))
			logger.Write([]byte(s))
		}
		return
	}

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
				doAccept(convo, c, "")
			case smtpd.RCPTTO:
				if decider(pRto, evt, c, convo, "") {
					continue
				}
				trans.rcptto = append(trans.rcptto, evt.Arg)
				if minphase == "to" {
					gotsomewhere = true
				}
				doAccept(convo, c, "")
			case smtpd.DATA:
				if decider(pData, evt, c, convo, "") {
					continue
				}
				if minphase == "data" {
					gotsomewhere = true
				}
				doAccept(convo, c, "")
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
			trans.cipher = convo.TLSState.CipherSuite
			trans.servername = convo.TLSState.ServerName
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
				doAccept(convo, c, transid)
			}
		case smtpd.TLSERROR:
			// any TLS error means we'll avoid offering TLS
			// to this source IP for a while.
			notls.Add(trans.rip, tlsTimeout)
			sesscounts = false
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
	case !gotsomewhere && sesscounts:
		yakkers.Add(trans.rip, yakTimeout)
		// See if this transaction has pushed the client over the
		// edge to becoming a yakker. If so, report it to the SMTP
		// log.
		hit, cnt = yakkers.Lookup(trans.rip, yakTimeout)
		if hit && cnt >= yakCount && smtplog != nil {
			s := fmt.Sprintf("! %s added as a yakker at hit %d\n", trans.rip, cnt)
			logger.Write([]byte(s))
		}
	case yakCount > 0 && gotsomewhere:
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

// loadCerts loads certificates and keys from files. If there are
// multiple certs and keys, the list of each must be comma-separated,
// eg 'cert1.crt,cert2.crt' and 'key1.key,key2.key'.
func loadCerts(certs, keys string) ([]tls.Certificate, error) {
	clist := strings.Split(certs, ",")
	klist := strings.Split(keys, ",")
	if len(clist) != len(klist) {
		return nil, fmt.Errorf("Different number of certificates and keys")
	}
	res := make([]tls.Certificate, 0, len(clist))
	for i := range clist {
		cert, err := tls.LoadX509KeyPair(clist[i], klist[i])
		if err != nil {
			if len(clist) > 1 {
				return nil, fmt.Errorf("while loading %s & %s: %v", clist[i], klist[i], err)
			}
			return nil, err
		}
		res = append(res, cert)
	}
	return res, nil
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
var connfile string

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
func buildRules(stdrules bool) []*Rule {
	var outbuf bytes.Buffer

	if stdrules {
		// We must split these rules because otherwise the
		// to-has requirement would defer this rule until RCPT
		// TO even if the MAIL FROM was bad.
		fmt.Fprintf(&outbuf, "reject from-has bad,route\n")
		fmt.Fprintf(&outbuf, "reject to-has bad,route\n")
		// We never accept blank EHLO/HELO, although smtpd
		// will.
		fmt.Fprintf(&outbuf, "reject helo-has none\n")
	}

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
(Well, godoc output. cmd/doc.go in the source.)

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
	var pprofserv string
	var force, nostdrules bool
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
	flag.BoolVar(&nostdrules, "nostdrules", false, "do not use standard basic rules")
	flag.StringVar(&pprofserv, "pprof", "", "host:port for net/http/pprof performance monitoring server")
	flag.StringVar(&connfile, "conncfg", "", "filename of per-connection parameters")

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
		var err error
		certs, err = loadCerts(certfile, keyfile)
		if err != nil {
			die("error loading TLS cert(s) from %s & %s: %v\n", certfile, keyfile, err)
		}

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

	if connfile != "" {
		_, err := loadConnFile(connfile)
		if err != nil {
			die("cannot load per-connection config information from '%s': %s\n", connfile, err)
		}
	}

	// Turn the rules file string into filenames and verify that they
	// all parse.
	// first we must build our base rules, in case things explode
	baserules := buildRules(!nostdrules)
	genStallRules()
	// start up our 'suppress duplicate warnings' backend
	// goroutine now, since setupRules() may wind up calling it.
	go warnbackend()

	// basic check for presence and readability.
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
	// Try to load the rules.
	_, isgood := setupRules(baserules)
	if !isgood {
		// we must call warnonce() to make sure that the warn once
		// backend has actually printed earlier warning messages.
		// otherwise our print-and-exit is in a race with the
		// backend goroutine running, a race that the backend
		// goroutine can easily lose.
		warnonce("")
		die("not continuing when there are problems in the rules files.\n")
	}

	switch minphase {
	case "ehlo":
		// ehlo is a synonym for helo
		minphase = "helo"
	case "from", "to", "data", "message", "accepted", "helo":
		// it's okay
	default:
		die("invalid -minphase '%s': must be helo/ehlo, from, to, data, message, or accepted\n", minphase)
	}

	// Start monitoring HTTP server if we've been asked to do so.
	if pprofserv != "" {
		runtime.MemProfileRate = 1
		go func() {
			http.ListenAndServe(pprofserv, nil)
		}()
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
		go process(cid, nc, certs, logf, slogf, baserules)
		cid++
	}
}
