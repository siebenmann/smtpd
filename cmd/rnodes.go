//
// Rule nodes and rule evaluation and so on.
package main

import (
	"fmt"
	"sort"
	"strings"
)

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

	// address options
	oUnqualified
	oRoute
	oQuoted
	oNoat
	oGarbage
	oBad = oUnqualified | oRoute | oNoat | oGarbage
)

type Result bool

type Rule struct {
	// Rule cannot be evaluated until this phase; at most Rto right now.
	requires Phase

	deferto Phase // Rule result is deferred until this phase
	result  Action

	expr Expr // expression to evaluate
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

// Expr is an expression node, aka an AST node.
type Expr interface {
	Eval(c *Context) Result
	String() string
}

// Structural nodes

// normal running 'thing1 thing2 ...'
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

// not <thing>
type NotN struct {
	node Expr
}

func (n *NotN) Eval(c *Context) (r Result) {
	return !n.node.Eval(c)
}
func (n *NotN) String() string {
	return "not " + n.node.String()
}

// thing1 or thing2
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

// All always matches.
type AllN struct{}

func (a *AllN) String() string {
	return "all"
}
func (a *AllN) Eval(c *Context) (r Result) {
	return true
}

// True if TLS is on.
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

//
// from/to/helo/host matchers. All of these have a common pattern:
// they take an argument that may be a filename and they do either
// address or host matching. host and to iterate over the valid
// hostnames and rcptto address respectively, helo/from just look
// at the EHLO name or the MAIL FROM. We handle all of these with
// one core object.
// OUT OF DATE, rcptto matching is singleton now.

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

// ------
//
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
