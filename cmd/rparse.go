//
// Parse rules.
// This is currently a skeleton that parses but does nothing except choke
// on errors.
//

package main

import (
	"fmt"
)

// grammar:
// a squence of rules
//
// rule  -> [phase] [toall] what orl EOL|EOF
// phase -> @HELO | @FROM | @TO | @DATA | @MESSAGE
// what  -> ACCEPT | REJECT | STALL
// andl  -> orl [andl]
// orl   -> term [OR orl]
// term  -> NOT term
//          ( andl )
//          TLS ON|OFF
//          DNS DNS-OPT[,DNS-OPT]
//          HELO-HAS HELO-OPT[,HELO-OPT]
//          FROM-HAS|TO-HAS ADDR-OPT[,ADDR-OPT]
//          FROM|TO|HELO|HOST arg
//          ALL
// arg   -> VALUE
//          FILENAME
// arg actually is 'anything', keywords become values in it.

type Parser struct {
	l      *lexer
	curtok item

	currule *Rule
}

func (p *Parser) consume() {
	// EOF is sticky because we pretend that it is an end of line
	// marker.
	if p.curtok.typ == itemEOF {
		return
	}
	if p.curtok.typ == itemError {
		panic("trying to consume an error")
	}
	p.curtok = p.l.nextItem()
}

func (p *Parser) isEol() bool {
	return p.curtok.typ == itemEOL || p.curtok.typ == itemEOF
}

func (p *Parser) genError(msg string) *string {
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
		return &s
	default:
		fnd = fmt.Sprintf("'%s'", p.curtok.val)
	}
	s := fmt.Sprintf("at line %d char %d: %s: found %s", ln, lp, msg, fnd)
	return &s
}
func (p *Parser) lineError(msg string) *string {
	ln, _ := p.l.lineInfo(p.curtok.pos)
	s := fmt.Sprintf("at line %d: %s", ln, msg)
	return &s
}
func (p *Parser) posError(msg string) *string {
	ln, lp := p.l.lineInfo(p.curtok.pos)
	s := fmt.Sprintf("at line %d char %d: %s", ln, lp, msg)
	return &s
}

func (p *Parser) pNot() (expr Expr, err *string) {
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

func (p *Parser) pParen() (expr Expr, err *string) {
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

func (p *Parser) pArg() (arg string, err *string) {
	if p.curtok.typ < itemHasValue {
		return "", p.genError("expected argument")
	}
	arg = p.curtok.val
	p.consume()
	return
}

func (p *Parser) pOnOff() (on bool, err *string) {
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
var minReq = map[itemType]Phase{
	itemFrom: pMfrom, itemHelo: pHelo, itemTo: pRto,
	itemFromHas: pMfrom, itemToHas: pRto, itemHeloHas: pHelo,
	// We can't be sure that TLS is set up until we've seen a
	// MAIL FROM, because the first HELO/EHLO will be without
	// TLS and then they will STARTTLS again.
	itemTls: pMfrom,
}

var heloMap = map[itemType]Option{
	itemHelo: oHelo, itemEhlo: oEhlo, itemNone: oNone, itemNodots: oNodots,
	itemBareip: oBareip,
}
var dnsMap = map[itemType]Option{
	itemNodns: oNodns, itemInconsistent: oInconsist, itemNoforward: oNofwd,
	itemGood: oGood,
}
var addrMap = map[itemType]Option{
	itemUnqualified: oUnqualified, itemRoute: oRoute, itemQuoted: oQuoted,
	itemNoat: oNoat, itemGarbage: oGarbage, itemBad: oBad,
}
var mapMap = map[itemType]map[itemType]Option{
	itemFromHas: addrMap, itemToHas: addrMap,
	itemHeloHas: heloMap,
	itemDns:     dnsMap,
}

func (p *Parser) pCommaOpts(m map[itemType]Option) (opt Option, err *string) {
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

func (p *Parser) pTerm() (expr Expr, err *string) {
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
	var arg string
	var ison bool
	var opts Option
	switch ct {
	case itemFrom, itemTo, itemHelo, itemHost:
		p.consume()
		arg, err = p.pArg()
	case itemTls:
		p.consume()
		ison, err = p.pOnOff()
	case itemAll:
		p.consume()
		return &AllN{}, nil
	case itemFromHas, itemToHas, itemDns, itemHeloHas:
		p.consume()
		opts, err = p.pCommaOpts(mapMap[ct])
	default:
		// Since we are bottoming out on the parsing stack,
		// we need to start shuttling unrecognized things
		// back up it here.
		return nil, nil
	}

	if err != nil {
		return nil, err
	}
	switch ct {
	case itemFrom:
		return newFromNode(arg), nil
	case itemTo:
		return newToNode(arg), nil
	case itemHelo:
		return newHeloNode(arg), nil
	case itemHost:
		return newHostNode(arg), nil
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
		panic("should be impossible")
	}
}

// We cheat by not recursing and simply looping.
func (p *Parser) pAndl() (expr Expr, err *string) {
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
	switch {
	case len(exp.nodes) > 1:
		return exp, nil
	case len(exp.nodes) == 1:
		return exp.nodes[0], nil
	default:
		return nil, nil
	}
}

func (p *Parser) pOrl() (expr Expr, err *string) {
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
		return nil, p.posError("empty right side of an OR")
	}
	exp.right = er
	return exp, err
}

var phases = map[itemType]Phase{
	itemAHelo: pHelo, itemAFrom: pMfrom, itemATo: pRto, itemAData: pData,
	itemAMessage: pMessage,
}

func (p *Parser) pPhase() {
	ct := p.curtok.typ
	if phases[ct] != pAny {
		p.currule.deferto = phases[ct]
		p.consume()
	}
}

// A rule is [phase] what [orl]
// *rules are the only thing that consume end of line markers*
// the lexer does not feed us empty lines, so there must be a
// word start in here. As a result we ignore this possibility.
var actions = map[itemType]Action{
	itemAccept: aAccept, itemReject: aReject, itemStall: aStall,
}

func (p *Parser) pRule() (r *Rule, err *string) {
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
	if p.isEol() {
		// we check for errors before consuming the EOL so that
		// the line numbers come out right in error messages.
		if p.currule.deferto != pAny &&
			p.currule.deferto < p.currule.requires {
			return nil, p.lineError("rule specifies a phase lower than its operations require, does not make sense")
		}
		// remove trivial root of 'defer to now'.
		if p.currule.deferto == p.currule.requires {
			p.currule.deferto = pAny
		}
		p.consume()
		return p.currule, err
	} else {
		return nil, p.genError("expecting end of line")
	}
}

// a file is a sequence of rules.
func (p *Parser) pFile() (rules []*Rule, err *string) {
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

func Parse(input string) (rules []*Rule, err *string) {
	l := lex(input)
	p := &Parser{l: l}
	p.curtok = l.nextItem()
	return p.pFile()
}
