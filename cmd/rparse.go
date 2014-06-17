//
package main

// Parse rules.
//
// our grammar:
// a file is a sequence of rules; each rule ends at end of line
//
// rule  -> [phase] [toall] what andl EOL|EOF
// phase -> @HELO | @FROM | @TO | @DATA | @MESSAGE
// what  -> ACCEPT | REJECT | STALL
// andl  -> orl [andl]
// orl   -> term [OR orl]
// term  -> NOT term
//          ( andl )
//          ALL
//          TLS ON|OFF
//          DNS DNS-OPT[,DNS-OPT]
//          HELO-HAS HELO-OPT[,HELO-OPT]
//          FROM-HAS|TO-HAS ADDR-OPT[,ADDR-OPT]
//          FROM|TO|HELO|HOST arg
//          IP IPADDR|CIDR|FILENAME
// arg   -> VALUE
//          FILENAME
// arg actually is 'anything', keywords become values in it.

import (
	"errors"
	"fmt"
	"net"
)

// our approach to lookahead is that parsing rules must deliberately
// consume the current token instead of getting it, looking at it,
// and then putting it back if they don't want it.
type parser struct {
	l       *lexer
	curtok  item
	currule *Rule
}

// consume the current token and advance to the next one
func (p *parser) consume() {
	// EOF is sticky because we pretend that it is an end of line
	// marker.
	if p.curtok.typ == itemEOF {
		return
	}
	if p.curtok.typ == itemError {
		// we panic because the rest of the code is supposed to not
		// do this. doing it anyways is an internal coding error.
		panic("trying to consume an error")
	}
	p.curtok = p.l.nextItem()
}

func (p *parser) isEol() bool {
	return p.curtok.typ == itemEOL || p.curtok.typ == itemEOF
}

// generate errors in various forms. the full form is for 'we expected Y
// but got X'. The other forms are for when the current token is not a
// useful part of the error.
func (p *parser) genError(msg string) error {
	ln, lp := p.l.lineInfo(p.curtok.pos)
	var fnd string
	switch p.curtok.typ {
	case itemEOF:
		fnd = "unexpected end of file"
	case itemEOL:
		fnd = "unexpected end of line"
	case itemError:
		// the real problem is that we hit a lexing error;
		// the msg we've been passed in is basically irrelevant.
		fnd = "lexing error: " + p.curtok.val
		s := fmt.Sprintf("at line %d char %d: lexing error: %s",
			ln, lp, p.curtok.val)
		return errors.New(s)
	default:
		fnd = fmt.Sprintf("'%s'", p.curtok.val)
	}
	s := fmt.Sprintf("at line %d char %d: %s, found %s", ln, lp, msg, fnd)
	return errors.New(s)
}
func (p *parser) lineError(msg string) error {
	ln, _ := p.l.lineInfo(p.curtok.pos)
	s := fmt.Sprintf("at line %d: %s", ln, msg)
	return errors.New(s)
}
func (p *parser) posError(msg string) error {
	ln, lp := p.l.lineInfo(p.curtok.pos)
	s := fmt.Sprintf("at line %d char %d: %s", ln, lp, msg)
	return errors.New(s)
}

// parse: NOT term
func (p *parser) pNot() (expr Expr, err error) {
	p.consume()
	exr := &NotN{}
	exr.node, err = p.pTerm()
	if err != nil {
		return nil, err
	}
	if exr.node == nil {
		return nil, p.genError("expected something to NOT")
	}
	return exr, err
}

// parse: ( andl )
func (p *parser) pParen() (expr Expr, err error) {
	p.consume()
	er, err := p.pAndl()
	if err != nil {
		return nil, err
	}
	if p.curtok.typ != itemRparen {
		return nil, p.genError("expecting closing ')'")
	}
	if er == nil {
		return nil, p.posError("empty parenthesized expression")
	}
	p.consume()
	return er, err
}

// parse: arg
// this rejects special things like EOL.
func (p *parser) pArg() (arg string, err error) {
	if p.curtok.typ < itemHasValue {
		return "", p.genError("expected argument")
	}
	arg = p.curtok.val
	p.consume()
	return
}

// parse: IP-ADDR|CIDR|FILENAME
// Unlike pArg, we know that IP addresses or CIDRs can never be
// tokenized as something other than an itemValue so we can
// immediately reject anything else.
func (p *parser) pIPArg() (arg string, err error) {
	switch p.curtok.typ {
	case itemFilename:
		arg = p.curtok.val
		p.consume()
		return
	case itemValue:
		arg = p.curtok.val
		if _, _, err := net.ParseCIDR(arg); err != nil && net.ParseIP(arg) == nil {
			return "", p.genError("argument is not a valid IP address or CIDR")
		}
		p.consume()
		return
	default:
		return "", p.genError("expected IP address, CIDR, or filename")

	}
}

// parse: ON|OFF
func (p *parser) pOnOff() (on bool, err error) {
	switch p.curtok.typ {
	case itemOn:
		p.consume()
		return true, nil
	case itemOff:
		p.consume()
		return false, nil
	default:
		return false, p.posError("expected on or off")
	}
}

// Minimum phase requirements for various things that cannot be evaluated
// at any time.
// This is used to set the overall phase requirement for the rule being
// generated
var minReq = map[itemType]Phase{
	itemFrom: pMfrom, itemHelo: pHelo, itemTo: pRto,
	itemFromHas: pMfrom, itemToHas: pRto, itemHeloHas: pHelo,
	// We can't be sure that TLS is set up until we've seen a
	// MAIL FROM, because the first HELO/EHLO will be without
	// TLS and then they will STARTTLS again.
	itemTls: pMfrom,
}

// Options for HELO-HAS, DNS, FROM-HAS, and TO-HAS. These map from lexer
// tokens to the option bitmap values that the token means.
var heloMap = map[itemType]Option{
	itemHelo: oHelo, itemEhlo: oEhlo, itemNone: oNone, itemNodots: oNodots,
	itemBareip: oBareip,
}
var dnsMap = map[itemType]Option{
	itemNodns: oNodns, itemInconsistent: oInconsist, itemNoforward: oNofwd,
	itemGood: oGood, itemExists: oExists,
}
var addrMap = map[itemType]Option{
	itemUnqualified: oUnqualified, itemRoute: oRoute, itemQuoted: oQuoted,
	itemNoat: oNoat, itemGarbage: oGarbage, itemBad: oBad,
}

// map from the starting token to the appropriate option map.
var mapMap = map[itemType]map[itemType]Option{
	itemFromHas: addrMap, itemToHas: addrMap,
	itemHeloHas: heloMap,
	itemDns:     dnsMap,
}

// parse: any variant of comma-separated options. We are called with
// a map that tells us which particular set of options to use and what
// they map to.
func (p *parser) pCommaOpts(m map[itemType]Option) (opt Option, err error) {
	for {
		ct := p.curtok.typ
		if m[ct] == oZero {
			return oZero, p.genError("expected valid option")
		}
		opt |= m[ct]
		p.consume()
		if p.curtok.typ == itemComma {
			p.consume()
		} else {
			break
		}
	}
	return opt, nil
}

// parse: a term. This is the big production at the bottom of the parse
// stack.
func (p *parser) pTerm() (expr Expr, err error) {
	ct := p.curtok.typ
	if ct == itemNot {
		return p.pNot()
	}
	if ct == itemLparen {
		return p.pParen()
	}

	// set phase requirement, if any.
	if minReq[ct] != pAny && minReq[ct] > p.currule.requires {
		p.currule.requires = minReq[ct]
	}

	// get argument
	// we split handling terms into separate 'get argument' and
	// 'generate expression node' operations because everything
	// that takes an argument has to check if the attempt to get
	// an argument ran into an error (and a number of things have
	// common operations but separate expression nodes).
	var arg string
	var ison bool
	var opts Option
	switch ct {
	case itemFrom, itemTo, itemHelo, itemHost:
		p.consume()
		arg, err = p.pArg()
	case itemIp:
		p.consume()
		arg, err = p.pIPArg()
	case itemTls:
		p.consume()
		ison, err = p.pOnOff()
	case itemAll:
		// directly handle 'all' here since it has no argument.
		p.consume()
		return &AllN{}, nil
	case itemFromHas, itemToHas, itemDns, itemHeloHas:
		p.consume()
		opts, err = p.pCommaOpts(mapMap[ct])
	default:
		// The current token is not actually a valid term.
		// Since we are bottoming out on the parsing stack,
		// we need to start shuttling unrecognized things
		// back up it here.
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	// generate the expression node for the term now that we have a
	// valid argument.
	switch ct {
	case itemFrom:
		return newFromNode(arg), nil
	case itemTo:
		return newToNode(arg), nil
	case itemHelo:
		return newHeloNode(arg), nil
	case itemHost:
		return newHostNode(arg), nil
	case itemIp:
		return newIPNode(arg), nil
	case itemFromHas:
		return newFromHasOpt(opts), nil
	case itemToHas:
		return newToHasOpt(opts), nil
	case itemDns:
		return newDnsOpt(opts), nil
	case itemHeloHas:
		return newHeloOpt(opts), nil
	case itemTls:
		return &TlsN{on: ison}, nil
	default:
		// we should have trapped not-a-term above.
		// reaching here is a coding error.
		panic("should be impossible")
	}
}

// parse: orl -> term [OR orl]
func (p *parser) pOrl() (expr Expr, err error) {
	exp := &OrN{}
	er, err := p.pTerm()
	if err != nil {
		return nil, err
	}
	if p.curtok.typ != itemOr {
		return er, err
	}
	if er == nil {
		return nil, p.posError("empty left side of an or")
	}
	exp.left = er
	p.consume()
	er, err = p.pOrl()
	if err != nil {
		return nil, err
	}
	if er == nil {
		// We get here for two reasons: either we ran out of stuff
		// or we hit something that should have been a term but
		// isn't. We need to give different errors or I get really
		// confused.
		if p.isEol() || p.curtok.typ == itemRparen {
			return nil, p.posError("empty right side of an OR")
		}
		return nil, p.genError("expecting match operation")
	}
	exp.right = er
	return exp, err
}

// parse: andl -> orl [andl]
// We cheat by not recursing and simply looping.
func (p *parser) pAndl() (expr Expr, err error) {
	exp := &AndL{}
	for {
		er, err := p.pOrl()
		if err != nil {
			return nil, err
		}
		if er == nil {
			break
		}
		exp.nodes = append(exp.nodes, er)
	}
	// we suppress length-1 AndLs in favour of just returning the
	// underlying expression.
	// among other things, this makes us round-trip rules successfully;
	// otherwise we would accrete an extra andl node every round trip.
	switch {
	case len(exp.nodes) > 1:
		return exp, nil
	case len(exp.nodes) == 1:
		return exp.nodes[0], nil
	default:
		// this means we didn't actually parse anything because
		// the chain orl -> term wound up with term returning
		// nothing.
		return nil, nil
	}
}

// parse: [phase]
var phases = map[itemType]Phase{
	itemAHelo: pHelo, itemAFrom: pMfrom, itemATo: pRto, itemAData: pData,
	itemAMessage: pMessage,
}

func (p *parser) pPhase() {
	ct := p.curtok.typ
	if phases[ct] != pAny {
		p.currule.deferto = phases[ct]
		p.consume()
	}
}

// Parse a rule. A rule is [phase] what [orl]
// *rules are the only thing that consume end of line markers*
// the lexer does not feed us empty lines, so there must be a
// word start in here. As a result we ignore this possibility.
var actions = map[itemType]Action{
	itemAccept: aAccept, itemReject: aReject, itemStall: aStall,
}

func (p *parser) pRule() (r *Rule, err error) {
	p.currule = &Rule{}
	// bail if we are sitting on an EOF.
	if p.curtok.typ == itemEOF {
		return nil, nil
	}

	p.pPhase()
	ct := p.curtok.typ
	if actions[ct] == aError {
		return nil, p.genError("expecting an action")
	}
	p.currule.result = actions[ct]
	p.consume()
	p.currule.expr, err = p.pAndl()
	if err != nil {
		return nil, err
	}
	if p.currule.expr == nil {
		return nil, p.lineError("rule needs at least one operation, perhaps 'all'")
	}
	if !p.isEol() {
		// This is technically 'expecting end of line' but that
		// is not a useful error. What it really means is that
		// we ran into something that is not an operation down
		// in the depths of pTerm and it bubbled up to here.
		return nil, p.genError("expecting an operation")
	}
	// we check for errors before consuming the EOL so that
	// the line numbers come out right in error messages.
	if p.currule.deferto != pAny && p.currule.deferto < p.currule.requires {
		return nil, p.lineError("rule specifies a phase lower than its operations require so we cannot satisfy the phase requirement")
	}
	// If this rule wants to be defered to the phase it requires
	// anyways, we remove the deferto marker. This helps out
	// rules evaluation.
	if p.currule.deferto == p.currule.requires {
		p.currule.deferto = pAny
	}
	p.consume()
	return p.currule, err
}

// a file is a sequence of rules.
func (p *parser) pFile() (rules []*Rule, err error) {
	for {
		r, e := p.pRule()
		if e != nil {
			return rules, e
		}
		if r != nil {
			rules = append(rules, r)
		}
		if p.curtok.typ == itemEOF {
			break
		}
	}
	return rules, nil
}

// Parse an input string into a set of rules and a possible error.
// If there is an error, you must ignore the rules.
func Parse(input string) (rules []*Rule, err error) {
	l := lex(input)
	p := &parser{l: l}
	// we must prime the current token with the first token in the
	// file.
	p.curtok = l.nextItem()
	return p.pFile()
}
