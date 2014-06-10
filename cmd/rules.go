//
// Processing rules:
// [phase] accept|reject|stall RULE ....
//
// [phase] defers processing the accept or reject until a particular phase
// is reached, eg 'data reject from @b.com' rejects MAIL FROM @b.com at the
// DATA phase.
//
// RULE is a series of operations. Primitives are:
//	from ADDRESS. to ADDRESS. helo HOST
//	address ADDR-OPTIONS, from-address ADDR-OPTIONS,
//	to-address ADDR-OPTIONS
//	greeted helo,ehlo,none,nodots,bareip
//	tls on|off, host HOST
//      dns nodns,inconsistent,noforward
// ADDR-OPTIONS: unqualified,route,quoted,noat,garbage,bad
// *-OPTIONS are or'd together. 'bad' is all but 'quoted'.
// 'host' is a verified DNS name. Maybe IP netblocks in the future?
// default is to AND all clauses.
// there is 'or' 'not' and '( ... )'.
//	reject helo somename from info@fbi.gov not to interesting@addr
//
// ADDRESS and HOST can be a filename.
//
// Rules take effect only at the point in the conversation when all
// information necessary for them to match is set. MAIL FROM:<> is
// always accepted.
// First matching rule wins.
// Default is to accept.
//
// phases: helo, mfrom, rto, data, message (DATA received)
//
// QUESTION: what does or do? Eg:
//	reject from info@fbi.gov to fred@barney or to joe@jim
// ... rejects from: info@fbi.gov, to either fred or joe.
package main

var defaultRules = `
reject address bad
`

// parsing and lexing in go:
// http://cuddle.googlecode.com/hg/talk/lex.html
// http://golang.org/cmd/yacc/
