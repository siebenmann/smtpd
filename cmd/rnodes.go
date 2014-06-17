//
package main

// Rule nodes and rule evaluation and so on.

import (
	"fmt"
	"sort"
	"strings"
)

// Phase is the SMTP conversation phase
type Phase int

const (
	pAny Phase = iota
	pHelo
	pMfrom
	pRto
	pData
	pMessage

	pMax
)

var pMap = map[Phase]string{
	pAny: "@any", pHelo: "@helo", pMfrom: "@from",
	pRto: "@to", pData: "@data", pMessage: "@message",
}

func (p Phase) String() string {
	return pMap[p]
}

// Action is the action to take in response to a successful rule
// match.
type Action int

// Actions are in order from weakest (accept) to strongest (reject)
const (
	aError Action = iota
	aNoresult
	aAccept
	aStall
	aReject
)

var aMap = map[Action]string{
	aError: "ERROR", aAccept: "accept", aReject: "reject", aStall: "stall",
	aNoresult: "no result",
}

func (a Action) String() string {
	return aMap[a]
}

// Option is bitmaps of all options for from-has/to-has, helo-has, and dns
// all merged into one type for convenience and my sanity.
type Option uint64

const (
	oZero Option = iota

	// EHLO/HELO options
	oHelo Option = 1 << iota
	oEhlo
	oNone
	oNodots
	oBareip

	// DNS options
	oNodns
	oInconsist
	oNofwd
	oGood
	oExists

	// address options
	oUnqualified
	oRoute
	oQuoted
	oNoat
	oGarbage
	oBad = oUnqualified | oRoute | oNoat | oGarbage
)

// Result is the result of evaluating a rule expression. Currently it
// is either true or false; in the future it may also include 'Defer'.
type Result bool

// Rule represents a single rule, bundling together various information
// about what it needs and results in with the expression it evaluates.
type Rule struct {
	expr     Expr // expression to evaluate
	result   Action
	requires Phase // Rule requires data from this phase; at most pRto now
	deferto  Phase // Rule wants to be deferred to this phase

	// The rule is that if deferto is set it is always larger than
	// requires. We don't allow '@from accept to ...' or similar
	// gimmicks; it's explicitly an error in the parser.
}

func (r *Rule) String() string {
	if r.deferto != pAny {
		return fmt.Sprintf("<%v: %v %v %s >", r.requires,
			r.deferto, r.result, r.expr.String())
	} else {
		return fmt.Sprintf("<%v: %v %s >", r.requires, r.result,
			r.expr.String())
	}
}

// Expr is an expression node, aka an AST node. Expr nodes may be
// structural (eg and and or nodes) or terminal nodes (matchers).
type Expr interface {
	Eval(c *Context) Result
	String() string
}

// Structural nodes

// AndL is our normal running 'thing1 thing2 ...'
type AndL struct {
	nodes []Expr
}

func (a *AndL) Eval(c *Context) (r Result) {
	for i := range a.nodes {
		r = a.nodes[i].Eval(c)
		if !r {
			return r
		}
	}
	return true
}
func (a *AndL) String() string {
	var l []string
	for i := range a.nodes {
		l = append(l, a.nodes[i].String())
	}
	return fmt.Sprintf("( %s )", strings.Join(l, " "))
}

// NotN is not <thing>
type NotN struct {
	node Expr
}

func (n *NotN) Eval(c *Context) (r Result) {
	return !n.node.Eval(c)
}
func (n *NotN) String() string {
	return "not " + n.node.String()
}

// OrN is thing1 or thing2
type OrN struct {
	left, right Expr
}

func (o *OrN) String() string {
	return fmt.Sprintf("( %s or %s )", o.left.String(), o.right.String())
}
func (o *OrN) Eval(c *Context) (r Result) {
	r = o.left.Eval(c)
	if r {
		return r
	}
	return o.right.Eval(c)
}

//
// ---
// Terminal nodes that match things.
//

// AllN is all; it always matches
type AllN struct{}

func (a *AllN) String() string {
	return "all"
}
func (a *AllN) Eval(c *Context) (r Result) {
	return true
}

// TlsN is true if TLS is on. It is 'tls on|off'.
type TlsN struct {
	on bool
}

func (t *TlsN) String() string {
	if t.on {
		return "tls on"
	} else {
		return "tls off"
	}
}
func (t *TlsN) Eval(c *Context) (r Result) {
	return t.on == c.trans.tlson
}

// MatchN is a general matcher for from/to/helo/host. All of these have
// a common pattern: they take an argument that may be a filename or a
// pattern and they do either address or host matching of some data source
// against it. Because 'host' matches against all verified host names,
// they all do list-matching; from/to/helo simply wrap up their single
// piece of data in a list.
type MatchN struct {
	what, arg string
	// match a literal against a pattern. Either matchHost or matchAddress
	matcher func(string, string) bool
	// get an array of strings of literals to match against.
	// from and helo have one-element arrays.
	getter func(*Context) []string
}

func (m *MatchN) String() string {
	return fmt.Sprintf("%s %s", m.what, m.arg)
}

// on an empty list, the entire rule should miss.
// TODO: not sure!
func (m *MatchN) Eval(c *Context) Result {
	plist := c.getMatchList(m.arg)
	if len(plist) == 0 {
		c.rulemiss = true
		return false
		// we might as well return here, we're not matching.
	}
	for _, p := range plist {
		for _, e := range m.getter(c) {
			if m.matcher(e, p) {
				return true
			}
		}
	}
	return false
}

func newHeloNode(arg string) Expr {
	return &MatchN{what: "helo", arg: arg, matcher: matchHost,
		getter: func(c *Context) []string {
			return []string{c.heloname}
		},
	}
}

func newHostNode(arg string) Expr {
	return &MatchN{what: "host", arg: arg, matcher: matchHost,
		getter: func(c *Context) []string {
			return c.trans.rdns.verified
		},
	}
}

func newFromNode(arg string) Expr {
	return &MatchN{what: "from", arg: arg, matcher: matchAddress,
		getter: func(c *Context) []string {
			return []string{c.from}
		},
	}
}

func newToNode(arg string) Expr {
	return &MatchN{what: "to", arg: arg, matcher: matchAddress,
		getter: func(c *Context) []string {
			return []string{c.rcptto}
		},
	}
}

func newIPNode(arg string) Expr {
	return &MatchN{what: "ip", arg: arg, matcher: matchIp,
		getter: func(c *Context) []string {
			return []string{c.trans.rip}
		},
	}
}

// ------

// OptionN is the general matcher for options.
// Options have getter functions that interrogate the context to determine
// what is the case. Those live in rules.go.
type OptionN struct {
	what   string
	opts   Option
	getter func(*Context) Option
}

func (t *OptionN) Eval(c *Context) (r Result) {
	opt := t.getter(c)
	return t.opts&opt > 0
}
func (t *OptionN) String() string {
	var l []string
	opts := t.opts
	if (opts & oBad) == oBad {
		l = append(l, "bad")
		opts = opts - oBad
	}
	for k, v := range revMap {
		if (k & opts) == k {
			l = append(l, v)
		}
	}
	// remember, Go map traversal order is deliberately unpredictable
	// we have to make it predictable to have something we can round
	// trip.
	sort.Strings(l)
	return fmt.Sprintf("%s %s", t.what, strings.Join(l, ","))
}

// GORY HACK. Construct inverse opts mapping through magic knowledge
// of both the lexer and the parser. We're all very friendly here,
// right?
func optsReverse() map[Option]string {
	rev := make(map[Option]string)
	revi := make(map[itemType]string)
	for s, i := range keywords {
		revi[i] = s
	}
	for _, m := range mapMap {
		for k, v := range m {
			rev[v] = revi[k]
		}
	}
	return rev
}

var revMap = optsReverse()

// -- create them.
func newDnsOpt(o Option) Expr {
	return &OptionN{what: "dns", opts: o, getter: dnsGetter}
}

func newHeloOpt(o Option) Expr {
	return &OptionN{what: "helo-has", opts: o, getter: heloGetter}
}

func getFromOpts(c *Context) Option {
	return getAddrOpts(c.from)
}
func newFromHasOpt(o Option) Expr {
	return &OptionN{what: "from-has", opts: o, getter: getFromOpts}
}

func getToOpts(c *Context) Option {
	return getAddrOpts(c.rcptto)
}
func newToHasOpt(o Option) Expr {
	return &OptionN{what: "to-has", opts: o, getter: getToOpts}
}
