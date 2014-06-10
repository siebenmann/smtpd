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
// rule  -> phase what orl EOL|EOF
//          what andl EOL|EOF
// phase -> HELO | MFROM | RTO | DATA | MESSAGE
// what  -> ACCEPT | REJECT | STALL
// andl  -> orl [andl]
// orl   -> term [OR orl]
// term  -> NOT term
//          ( andl )
//          TLS ON|OFF
//          DNS DNS-OPT[,DNS-OPT]
//          GREETED GREETED-OPT[,GREETED-OPT]
//          ADDRESS|FROM-ADDRESS|TO-ADDRESS ADDR-OPT[,ADDR-OPT]
//          FROM|TO|HELO|HOST arg
// arg   -> VALUE
//          FILENAME

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
		fnd = "lexing error: " + p.curtok.val
	default:
		fnd = p.curtok.val
	}
	s := fmt.Sprintf("at line %d char %d: %s: found '%s'", ln, lp, msg, fnd)
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
		return nil, p.genError("empty parenthesized expression")
	}
	p.consume()
	return er, err
}

func (p *Parser) pArg(t *TempN) (good bool, err *string) {
	if p.curtok.typ < itemHasValue {
		return false, nil
	}
	t.arg = p.curtok.val
	p.consume()
	return true, nil
}

// Minimum phase requirements for various things that cannot be evaluated
// at any time.
var minReq = map[itemType]Phase{
	itemFrom: pMfrom, itemHelo: pHelo, itemTo: pRto,
	// because 'address ..' applies to both MAIL FROM and RCPT TO,
	// it can't be processed until we start seeing RCPT TO or it
	// may miss.
	itemAddress: pRto, itemFromAddr: pMfrom, itemToAddr: pRto,
	itemGreeted: pHelo,
	// We can't be sure that TLS is set up until we've seen a
	// MAIL FROM, because the first HELO/EHLO will be without
	// TLS and then they will STARTTLS again.
	itemTls: pMfrom,
}

func (p *Parser) pTerm() (expr Expr, err *string) {
	ct := p.curtok.typ
	if minReq[ct] != pAny && minReq[ct] > p.currule.requires {
		p.currule.requires = minReq[ct]
	}
	switch p.curtok.typ {
	case itemNot:
		return p.pNot()
	case itemLparen:
		return p.pParen()
	case itemFrom, itemTo, itemHelo, itemHost:
		t := &TempN{what: p.curtok.val}
		p.consume()
		good, err := p.pArg(t)
		if err != nil {
			return nil, err
		}
		if !good {
			return nil, p.genError("expected argument")
		}
		return t, err
	default:
		return nil, nil
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
		return nil, p.genError("empty left side of an or")
	}
	exp.left = er
	p.consume()
	er, err = p.pOrl()
	if err != nil {
		return nil, err
	}
	if er == nil {
		return nil, p.genError("empty right side of an OR")
	}
	exp.right = er
	return exp, err
}

var phases = map[itemType]Phase{
	itemHelo: pHelo, itemMfrom: pMfrom, itemRto: pRto, itemData: pData,
	itemMessage: pMessage,
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
	if p.isEol() {
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
