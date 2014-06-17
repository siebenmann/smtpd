//
package main

// Core of implementing command processing rules.
// The documentation below may be out of date. See 'RULES' in this
// directory for the more canonical documentation.
//
// Processing rules:
// [phase] accept|reject|stall RULE ....
//
// [phase] defers matching the rule until a particular phase is
// reached, eg '@data reject from @b.com' rejects MAIL FROM @b.com at
// the DATA phase.
//
// RULE is a series of operations. Primitives are:
//	from ADDRESS. to ADDRESS. helo-as HOST
//	from-has ADDR-OPTIONS, to-has ADDR-OPTIONS
//	helo-has helo,ehlo,none,nodots,bareip
//	tls on|off, host HOST
//	dns nodns,inconsistent,noforward,good,exists
//      all
// ADDR-OPTIONS: unqualified,route,quoted,noat,garbage,bad
// *-OPTIONS are or'd together. 'bad' is all but 'quoted'.
// 'host' is a verified DNS name. Maybe IP netblocks in the future?
// default is to AND all clauses.
// there is 'or' 'not' and '( ... )'.
//	reject helo somename from info@fbi.gov not to interesting@addr
//
// ADDRESS and HOST can be a filename. Filenames are recognized in
// three forms: '/a/file' (absolute), './a/rel' (explicitly relative),
// and 'file:<whatever>' (explicitly marked).
//
// rules about RCPT TO addresses match only the *current* RCPT TO
// address being considered.
//
// Rules take effect only at the point in the conversation when all
// information necessary for them to match is set.
// First matching rule wins.
//
// phases: @helo, @from, @to, @data, @message (DATA received)
//
// QUESTION: what does or do? Eg:
//	reject from info@fbi.gov to fred@barney or to joe@jim
// ... rejects from: info@fbi.gov, to either fred or joe.
//
// TODO: write standalone documentation, including on address and
// hostname patterns.
//

import (
	//"fmt"
	"github.com/siebenmann/smtpd"
	"net"
	"strings"
)

// parsing and lexing in go:
// http://cuddle.googlecode.com/hg/talk/lex.html
// http://golang.org/cmd/yacc/

// Context is the context for all rule evaluation. All expressions take
// a context structure and operate on the data found in it.
type Context struct {
	// all fields in trans are read-only. we access trans.tlson
	// and trans.rdns
	trans *smtpTransaction

	// these are shadow copies because we evaluate rules *before*
	// things are accepted and thus show up in the trans versions.
	helocmd  smtpd.Command
	heloname string
	from     string
	rcptto   string

	// The set of rules used for this context.
	ruleset []*Rule

	// if we defer an action due to handling MAIL FROM:<>, this is
	// the action
	deferred Action

	// A map of loaded files. Files are loaded as lists. An empty
	// list means the file could not be loaded.
	// This is used to avoid redundant reloading of files across
	// multiple rules and for multiple checks for eg RCPT TO.
	files map[string][]string

	// we should tempfail for internal reasons, eg tempfail on file
	// read
	tempfail bool
	// the current rule being evaluated should not succeed.
	// this is used if we try to match something against an empty
	// pattern file.
	// TODO: is this the right semantics? Does this actually WORK?
	// do we stop processing all rules on a rule miss?
	// it makes 'reject from /bad/people' and 'reject not to /good/ppl'
	// work, at least.
	rulemiss bool
}

func newContext(trans *smtpTransaction, rules []*Rule) *Context {
	c := &Context{trans: trans, ruleset: rules}
	c.files = make(map[string][]string)
	return c
}

// We pull the list out of c.files if it's already loaded.
func (c *Context) getMatchList(a string) []string {
	var fname string
	switch {
	case a[0] == '/' || strings.HasPrefix(a, "./"):
		fname = a
	case strings.HasPrefix(a, "file:"):
		fname = a[len("file:"):]
	default:
		return []string{strings.ToLower(a)}
	}

	if c.files[fname] != nil {
		return c.files[fname]
	}
	l := loadList(fname)
	if len(l) == 0 {
		c.files[fname] = []string{}
		return c.files[fname]
	}
	c.files[fname] = l
	return c.files[fname]
}

//
// Turn context information into Options
func dnsGetter(c *Context) (o Option) {
	if len(c.trans.rdns.verified) == 0 {
		o |= oNodns
	} else {
		// yes, yes, this is just 'not dns nodns'. So what?
		// It's convenient.
		o |= oExists
	}
	if len(c.trans.rdns.nofwd) > 0 {
		o |= oNofwd
	}
	if len(c.trans.rdns.inconsist) > 0 {
		o |= oInconsist
	}
	// We have good DNS if none of the above are true. This
	// implies that we have at least one verified DNS result
	// and none that are bad.
	if o == oZero {
		o = oGood
	}
	return
}

func heloGetter(c *Context) (o Option) {
	var hip string
	if c.helocmd == smtpd.HELO {
		o |= oHelo
	} else {
		o |= oEhlo
	}
	hn := c.heloname
	if hn == "" {
		return o | oNone | oNodots
	}
	idx1 := strings.IndexByte(hn, '.')
	idx2 := strings.IndexByte(hn, ':')
	if idx1 == -1 && idx2 == -1 {
		o |= oNodots
	}
	if net.ParseIP(hn) != nil {
		o |= oBareip
		hip = hn
	}

	if len(hn) > 2 && hn[0] == '[' && hn[len(hn)-1] == ']' {
		t := hn[1 : len(hn)-1]
		if net.ParseIP(t) != nil {
			hip = t
			o |= oProperip
		}
	}
	switch {
	case hip == c.trans.rip:
		o |= oRemip
	case hip == c.trans.lip:
		o |= oMyip
	case hip != "":
		o |= oOtherip
	}
	return
}

// Analyze an address for its malfunctions
// TODO: do this better in a more structured way.
func getAddrOpts(a string) (o Option) {
	if a == "" {
		return
	}
	idx := strings.IndexByte(a, '@')
	if idx == -1 {
		o |= oNoat
	} else {
		// We don't necessarily do everything right in the presence
		// of route addresses.
		if idx == 0 {
			idx2 := strings.IndexByte(a[1:], '@')
			// This is '@something' as an address, which is a
			// big fat FAIL.
			if idx2 == -1 {
				o |= oGarbage
			} else {
				o |= oRoute
			}
		}
		idx2 := strings.IndexByte(a[idx+1:], '.')
		if idx2 == -1 {
			o |= oUnqualified
		}
	}
	// Look for trailing craziness
	lp := len(a) - 1
	if a[0] == '<' || a[lp] == '>' || a[lp] == '"' || a[lp] == ']' || a[lp] == '.' || idx == lp {
		o |= oGarbage
	}
	// general crazy things
	if strings.Contains(a, "..") || strings.Contains(a, "@@") {
		o |= oGarbage
	}

	idx = strings.IndexByte(a, '"')
	if idx != -1 && idx != lp {
		o |= oQuoted
	}
	return
}

// -----

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

// Match addresses. We do not attempt to do complicated matching on
// crazy addresses, such as route addresses or addresses that have
// the @ at the end.
func matchAddress(addr string, pat string) bool {
	addr = strings.ToLower(addr)
	if (addr == "" && pat == "<>") || addr == pat {
		return true
	}
	idx := strings.IndexByte(addr, '@')
	if addr == "" || idx == 0 || idx == len(addr) {
		return false
	}
	// local name only technically matches 'local@' patterns.
	if idx == -1 {
		return (addr + "@") == pat
	}
	// match simple 'local@' or '@domain' patterns.
	domain := addr[idx:]
	if addr[:idx+1] == pat || domain == pat {
		return true
	}
	// Try partial domain matches, right down to '@' which matches
	// anything that had a domain at all.
	// Since the domain starts with an @ we must skip it when
	// setting things up.
	// As a consequence of this, a bare '@' matches everything.
	var ts string
	si := &sDotIter{s: domain[1:]}
	for ts != "@" {
		ts = "@" + si.Next()
		if ts == pat {
			return true
		}
	}
	// base case: we have '@dom.ain' and want to match a '@.dom.ain' entry
	ts = "@." + domain[1:]
	return ts == pat
}

// match a hostname against a hostname pattern
func matchHost(host string, pat string) bool {
	host = strings.ToLower(host)
	if host == pat || "."+host == pat {
		return true
	}
	si := &sDotIter{s: host}
	for h := si.Next(); h != ""; h = si.Next() {
		if h == pat {
			return true
		}
	}
	return false
}

// match an IP against a CIDR or a plain IP.
// unfortunately we can't do ParseIP once and pass the result in because
// of static types.
func matchIp(rip string, cidr string) bool {
	// rip comes from the connection so it should always be valid.
	// We call net.ParseIP() on cidr and then use .Equal() in case
	// people wrote the rule's IP address in a divergent way, for
	// example filling in leading zeroes in an IPv4 address's octets
	// (yes people do this sometimes). ParseIP() has the side effect
	// of canonicalizing all of that for us.
	ip := net.ParseIP(rip)
	ip2 := net.ParseIP(cidr)
	if ip.Equal(ip2) {
		return true
	}
	_, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipn.Contains(ip)
}

// ----

// Match a rule against every accepted RCPT TO. Returns true if the rule
// matches against any of them.
// MUTATES c.rcptto! This should be called only in ph > pRto, when the
// c.rcptto value is not well defined anyways.
func ruleForEachRcpt(r *Rule, c *Context) Result {
	for _, rcpt := range c.trans.rcptto {
		c.rcptto = rcpt
		res := r.expr.Eval(c)
		if res {
			return res
		}
		// The result on a rulemiss doesn't really matter,
		// since we skip the rule anyways.
		if c.rulemiss {
			return res
		}
	}
	return false
}

//
// Decide what to do in a given phase in a context, with evt being
// the event for the phase (we pull the command argument and the
// command out of it).
func Decide(ph Phase, evt smtpd.EventInfo, c *Context) Action {
	// Set our shadow copies from what will become the real
	// copies if we're successful.
	// We also clear c.deferred in MAIL FROM or HELO to handle
	// RSETs (or just people trying different MAIL FROMs).
	switch ph {
	case pHelo:
		c.helocmd = evt.Cmd
		c.heloname = evt.Arg
		c.deferred = aError
	case pMfrom:
		c.from = evt.Arg
		c.deferred = aError
	case pRto:
		c.rcptto = evt.Arg
	case pData, pMessage:
		// c.rcptto is not well defined in these phases, so
		// blank it out in case code is looking by accident.
		c.rcptto = ""
	}

	var ret Action
	ret = aNoresult
	//fmt.Printf("running in %s (old %s)\n", ph, c.last)

	for _, r := range c.ruleset {
		// Try to determine if we can run this rule.
		rp := r.requires
		rr := r.result
		switch {
		case rp > ph:
			// the rule's basic requirements mean we can't
			// satisfy it yet. skip.
			continue

		case r.deferto > ph:
			// This is a simple deferred rule that is not ready
			// yet. We can run it when its time comes up.
			continue

			// Things we still have to process now:
		case rr <= aAccept || r.deferto == ph:
			// Accept rules must always be checked because
			// they don't block us from continuing.
			// (so we do 'pass' here)
			// If we've hit the phase for a deferto rule,
			// it obviously has to run.

			// Final skip case:
		case (rp == pAny && ph > pHelo) || (rp != pAny && rp < ph):
			// We can skip aReject and aStall rules if they
			// require a phase before this one, because if
			// they matched they would have blocked us from
			// reaching here.
			continue
		}

		//fmt.Printf("evaling: %v", r)
		var res Result

		c.rulemiss = false
		if ph > pRto && rp >= pRto {
			// This rule depends on RCPT TO for data but
			// runs after then. We must run it past each
			// accepted RCPT TO value to see what happens.
			res = ruleForEachRcpt(r, c)
		} else {
			res = r.expr.Eval(c)
		}
		if c.rulemiss {
			//fmt.Printf(" ... rulemiss set, skip\n")
			continue
		}
		if res {
			ret = r.result
			//fmt.Printf(" matched and: %v\n", ret)
			break
		}

		//fmt.Printf("\n")
	}

	// Handle deferred results due to MAIL FROM:<>.
	// We replace the determined result regardless of what it
	// is, even if the deferred MAIL FROM:<> was a stall and the
	// result now is a reject, because that's what your rules said
	// to do.
	// We don't clear c.deferred because this result is now sticky;
	// it must apply to all RCPT TOs from now on. If the connection
	// is RSET, the result will be cleared in our initial section.
	// Implicity ph >= pRto, really ph == pRto, because we only set
	// c.deferred in pMfrom.
	if c.deferred > aAccept {
		ret = c.deferred
	}

	// Do we need to defer our result in order to accept a
	// MAIL FROM:<>?
	if ph == pMfrom && c.from == "" && ret > aAccept {
		c.deferred = ret
		ret = aAccept
	}

	//fmt.Printf("eval done, result: %v\n", ret)
	return ret
}
