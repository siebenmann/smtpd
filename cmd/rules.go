//
// Processing rules:
// [phase] accept|reject|stall RULE ....
//
// [phase] defers doing the accept or reject until a particular phase
// is reached, eg 'data reject from @b.com' rejects MAIL FROM @b.com at the
// DATA phase. Note that this rule is *matched* at the MAIL FROM phase.
//
// RULE is a series of operations. Primitives are:
//	from ADDRESS. to ADDRESS. helo HOST
//	from-has ADDR-OPTIONS, to-has ADDR-OPTIONS
//	greeted helo,ehlo,none,nodots,bareip
//	tls on|off, host HOST
//	dns nodns,inconsistent,noforward
//      all
// ADDR-OPTIONS: unqualified,route,quoted,noat,garbage,bad
// *-OPTIONS are or'd together. 'bad' is all but 'quoted'.
// 'host' is a verified DNS name. Maybe IP netblocks in the future?
// default is to AND all clauses.
// there is 'or' 'not' and '( ... )'.
//	reject helo somename from info@fbi.gov not to interesting@addr
//
// ADDRESS and HOST can be a filename.
//
// rules about RCPT TO addresses match only the *current* RCPT TO
// address being considered.
//
// Rules take effect only at the point in the conversation when all
// information necessary for them to match is set.
// First matching rule wins.
//
// phases: helo, mfrom, rto, data, message (DATA received)
//
// QUESTION: what does or do? Eg:
//	reject from info@fbi.gov to fred@barney or to joe@jim
// ... rejects from: info@fbi.gov, to either fred or joe.
//
// TODO: some easier way to handle deferring helo rejections to either
// after MAIL FROM non-<> or RCPT TO:
package main

import (
	"github.com/siebenmann/smtpd"
	"strings"
)

// parsing and lexing in go:
// http://cuddle.googlecode.com/hg/talk/lex.html
// http://golang.org/cmd/yacc/

// All rules evaluation happens within a context.
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
	// these store predetermined results for rules with meaningful
	// phase markers. When we reach the given phase, we simply take
	// the result instead of evaluating any further rules.
	results [pMax]Action
	// last phase we dealt with, to detect RSET situations and do
	// something about them.
	// TODO: figure out what to do about RSETs, repeated HELO/EHLO,
	// etc.
	last Phase

	// A map of loaded files. Files are loaded as lists. An empty
	// list means the file could not be loaded.
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

// This is currently a hack, as we load a map then turn it into a list
// when we could just load a list. And probably should.
func (c *Context) getMatchList(a string) []string {
	if a[0] != '/' {
		return []string{a}
	}
	if c.files[a] != nil {
		return c.files[a]
	}
	l := loadList(a)
	if l == nil {
		c.files[a] = []string{}
		return c.files[a]
	}
	var v []string
	for k, _ := range l {
		v = append(v, k)
	}
	c.files[a] = v
	return c.files[a]
}

//
// Turn context information into Options
func dnsGetter(c *Context) (o Option) {
	if len(c.trans.rdns.verified) == 0 {
		o |= oNodns
	}
	if len(c.trans.rdns.nofwd) > 0 {
		o |= oNofwd
	}
	if len(c.trans.rdns.inconsist) > 0 {
		o |= oInconsist
	}
	return
}

func heloGetter(c *Context) (o Option) {
	if c.helocmd == smtpd.HELO {
		o |= oHelo
	} else {
		o |= oEhlo
	}
	if c.heloname == "" {
		return o | oNone | oNodots
	}
	idx1 := strings.IndexByte(c.heloname, '.')
	idx2 := strings.IndexByte(c.heloname, ':')
	if idx1 == -1 && idx2 == -1 {
		o |= oNodots
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
		// an address without a domain automatically has an
		// unqualified domain too.
		o |= oNoat | oUnqualified
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

	idx = strings.IndexByte(a, '"')
	if idx != -1 && idx != lp {
		o |= oQuoted
	}
	return
}

// -----

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

//
// Decide what to do in a given phase in a context, with evt being
// the event for the phase (we pull the command argument and the
// command out of it).
func Decide(ph Phase, evt smtpd.EventInfo, c *Context) Action {
	// pending results?
	if c.results[ph] != aError {
		return c.results[ph]
	}

	// initial setup.
	switch ph {
	case pHelo:
		c.helocmd = evt.Cmd
		c.heloname = evt.Arg
	case pMfrom:
		c.from = evt.Arg
	case pRto:
		c.rcptto = evt.Arg
	}

	c.last = ph
	for _, r := range c.ruleset {
		// either this rule has already done everything it can or
		// we can't do it yet.
		// A pAny rule, ie one that has no specific prereqs, does
		// not need to fire above pHelo.
		rp := r.requires
		if (rp != pAny && rp != ph) || (rp == pAny && ph > pHelo) {
			continue
		}

		c.rulemiss = false
		res := r.expr.Eval(c)
		if c.rulemiss {
			continue
		}
		if !res {
			continue
		}

		// semantics: if you defer an action, we keep looking for
		// more actions now.
		if r.deferto != pAny {
			c.results[r.deferto] = r.result
		} else {
			return r.result
		}
	}
	return aNoresult
}
