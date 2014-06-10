//
// Rule nodes and rule evaluation and so on.
package main

import (
	"fmt"
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
)

var pMap = map[Phase]string{
	pAny: "any", pHelo: "helo", pMfrom: "mailfrom",
	pRto: "rcptto", pData: "data", pMessage: "message",
}

func (p Phase) String() string {
	return pMap[p]
}

type Action int

const (
	aError Action = iota
	aAccept
	aReject
	aStall
)

var aMap = map[Action]string{
	aError: "ERROR", aAccept: "accept", aReject: "reject", aStall: "stall",
}

func (a Action) String() string {
	return aMap[a]
}

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
		return fmt.Sprintf("<@%v: %v %v %s >", r.requires,
			r.deferto, r.result, r.expr.String())
	} else {
		return fmt.Sprintf("<@%v: %v %s >", r.requires, r.result,
			r.expr.String())
	}
}

type Expr interface {
	Eval(ti *TransInfo) (Result, error)
	String() string
}

type TransInfo struct {
	// to come
}

// Structural nodes
type AndL struct {
	nodes []Expr
}

func (a *AndL) Eval(ti *TransInfo) (r Result, e error) {
	for i, _ := range a.nodes {
		r, e = a.nodes[i].Eval(ti)
		if e != nil || !r {
			return r, e
		}
	}
	return true, nil
}
func (a *AndL) String() string {
	var l []string
	for i, _ := range a.nodes {
		l = append(l, a.nodes[i].String())
	}
	return fmt.Sprintf("( %s )", strings.Join(l, " "))
}

type NotN struct {
	node Expr
}

func (n *NotN) Eval(ti *TransInfo) (r Result, e error) {
	r, e = n.node.Eval(ti)
	if e != nil {
		return r, e
	}
	return !r, e
}
func (n *NotN) String() string {
	return "not " + n.node.String()
}

type OrN struct {
	left, right Expr
}

func (o *OrN) String() string {
	return fmt.Sprintf("( %s or %s )", o.left.String(), o.right.String())
}
func (o *OrN) Eval(ti *TransInfo) (r Result, e error) {
	r, e = o.left.Eval(ti)
	if e != nil || r {
		return r, e
	}
	return o.right.Eval(ti)
}

//
// ---
// Terminal nodes that match things.
//

// TEMPORARY HACK
type TempN struct {
	what string
	arg  string
}

func (t *TempN) String() string {
	return fmt.Sprintf("%s %s", t.what, t.arg)
}
func (t *TempN) Eval(ti *TransInfo) (r Result, err error) {
	return true, nil
}
