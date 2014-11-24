//
// Test parsing and some evaluating
// TODO: more tests
//
package main

import (
	"bufio"
	"fmt"
	"github.com/siebenmann/smtpd"
	"strings"
	"testing"
)

// all of these rules should parse
// we don't try to match them; this is just a parse test (and then
// a test that we can round-trip them through stringifying the rule
// and re-parsing it and the round trip is stable).
// These rules are parsed as a unit so comments, line continuations,
// etc are both allowed and tested.
var aParse = `
accept from a@b
@data reject to b@c or to fred or from a@b helo barney
stall from a@b not to d@e or (helo barney to charlie host fred)
reject helo somename from info@fbi.gov not to interesting@addr
reject helo-has none,nodots,helo from-has bad,quoted dns nodns
@message reject to-has garbage,route
accept dns good
reject dns noforward,inconsistent
accept ip 127.0.0.0/24 ip 127.0.0.10
reject ip 85.90.187.32/27 or host .edmpoint.com or ehlo .edmpoint.com
reject dnsbl sbl.spamhaus.org with message "listed in the SBL" \
		savedir jim note barney
set-with all with note "I am here"
@connect set-with ip 100.100.100.100 with tls-opt off
@connect set-with ip 100.200.200.100 with tls-opt no-client
reject source fred.com

# oh boy
set-with ip 127.0.0.1 with note a; all with note b;
	all with message "c"

# test all options for comma-separated things.
accept dns good or dns noforward,inconsistent,nodns or dns exists
accept tls on or tls off
accept from-has unqualified,route,quoted,noat,garbage,bad,resolves
accept to-has unqualified,route,quoted,noat,garbage,bad,baddom,unknown
accept helo-has helo,ehlo,none,nodots,bareip,properip,ip,myip,remip,otherip

# we assume /dev/null is always present, because we're Unix-biased like that.
include /dev/null
`

func TestParse(t *testing.T) {
	rules, err := Parse(aParse + allSuccess)
	if err != nil {
		t.Fatalf("Error reported: %s\n", err)
	}
	if len(rules) == 0 {
		t.Fatalf("No parse error but nothing found")
	}
	for i := range rules {
		r1 := rules[i].String()
		rls, err := Parse(r1)
		if err != nil || len(rls) != 1 {
			t.Fatalf("round tripping: %s\nerr: %s\nrules: %+v\n",
				r1, err, rls)
		}
		r2 := rls[0].String()
		if r2 != r1 {
			t.Fatalf("failed to round trip.\nstart:\t%s\nend:\t%s\n", r1, r2)
		}
		//fmt.Printf("%s\n", rules[i].String())
	}
}

// ----
// For many tests of rules evaluation we need a context.

// aList will become the synthetic file '/a/file'
var aList = `# This is a comment
INFO@FBI.GOV
root@

@example.com
postmaster@Example.Org
@.barney.net
# t
`

// ipList will become the synthetic file '/ips'
var ipList = `
127.0.0.0/8
# this should not generate an error even thought it would in the
# the actual rules.
not-valid
192.168.10.0/24
`

// Set up our standard context
func setupFile(c *Context, name, conts string) error {
	reader := bufio.NewReader(strings.NewReader(conts))
	a, err := readList(reader)
	if err != nil {
		return err
	}
	c.files[name] = a
	return nil
}
func setupContext(t *testing.T) *Context {
	// We must mimic the trailing '.' on real DNS results in order
	// to make sure we're really testing against an authentic setup.
	rd := &rDNSResults{[]string{"a.b.c.", "d.e.f."}, []string{"g."},
		[]string{"h.i."}}
	st := &smtpTransaction{
		rdns:  rd,
		tlson: true,
		rip:   "192.168.10.3",
		lip:   "127.0.0.1",
	}
	// TODO: should we call the real setup function and then start
	// stuffing values?
	c := &Context{trans: st,
		helocmd:   smtpd.EHLO,
		heloname:  "joebob.ben",
		from:      "jim@jones.com",
		rcptto:    "joe@example.com",
		files:     make(map[string][]string),
		dnsbl:     make(map[string]*Result),
		withprops: make(map[string]string),
	}

	var rt, rf Result
	rt = true
	c.dnsbl["3.10.168.192.nosuch.domain."] = &rt
	c.dnsbl["3.10.168.192.notthere.domi."] = &rf

	err := setupFile(c, "/a/file", aList)
	if err != nil {
		t.Fatalf("Error during read: %v", err)
	}
	err = setupFile(c, "/ips", ipList)
	if err != nil {
		t.Fatalf("Error during iplist read: %v", err)
	}
	c.files["/empty"] = []string{}
	return c
}

// -----

// all of the following rules should match with our standard artifical
// context
// As a side effect these matches test a number of the getter and
// matcher functions in rules.go
// Since all rules will parse, allSuccess is parsed as an entire file
// instead of line at a time.
var allSuccess = `
accept all
accept from jim@jones.com to joe@example.com not dns nodns
accept from JIM@JONES.com
accept to joe@ from @.com
accept dns inconsistent dns noforward
accept helo-has ehlo tls on
accept not helo-has nodots from @.net or dns nodns or to @.com
accept helo-has nodots or (from @jones.com to @example.com)
accept from jim@jones.com to info@fbi.gov or to joe@example.com
accept not (from jim@ to @logan)
accept all or to jim@example.com
accept not from-has noat
accept not to-has quoted
# these are both false because of the synthetic test environment
accept not from-has resolves
accept from-has baddom
# dns is not good because there are inconsistent and noforward stuff
accept not dns good
accept helo .ben
accept not helo-has bareip
accept host .b.c
accept host .f
# IP tests
accept ip 192.168.10.3 ip 192.168.10.0/24 ip /ips ip 192.168.010.003
accept not ip 127.0.0.10
# source tests
accept source .f
accept source .ben
accept source jones.com
accept not source example.com
`

// Verify that all rules in allSuccess do succeed.
func TestSuccess(t *testing.T) {
	c := setupContext(t)
	rules, err := Parse(allSuccess)
	if err != nil {
		t.Fatalf("error reported %s\n", err)
	}
	for i := range rules {
		c.rulemiss = false
		res := rules[i].check(c)
		if !res {
			t.Errorf("rule did not succeed: %v\n", rules[i])
		}
		if c.rulemiss {
			t.Errorf("rule set rulemiss: %v\n", rules[i])
		}
	}
}

// verify address matching for a file-based from rule.
// we include tests for properly lower-casing an address.
var inAddrs = []string{
	"INFO@FBI.GOV", "root@fred.com", "random@example.com",
	"postmaster@example.org", "root@example.com",
	"joe@fred.barney.net", "james@barney.net",
}
var outAddrs = []string{
	"fred@fbi.gov", "postmaster@example.net", "fred@random.org",
	"nosuch@james.net", "nosuch@barney.org",
}

func TestFileAddrMatching(t *testing.T) {
	c := setupContext(t)
	rules, e := Parse("accept from /a/file")
	if e != nil {
		t.Fatalf("parse error %v", e)
	}
	for _, in := range inAddrs {
		c.from = in
		if !rules[0].check(c) {
			t.Errorf("address list does not match %s", in)
		}
	}
	for _, out := range outAddrs {
		c.from = out
		if rules[0].check(c) {
			t.Errorf("address list matches %s", out)
		}
	}
}

// Test that we properly set c.rulemiss when a rule evaluation tries
// to check an empty file.
func TestEmptyFile(t *testing.T) {
	c := setupContext(t)
	rules, e := Parse("accept from file:/empty")
	if e != nil {
		t.Fatalf("parse error %v", e)
	}
	rules[0].check(c)
	if !c.rulemiss {
		t.Fatalf("rule did not set rulemiss")
	}
}

// Test 'helo-has' matching. This implicitly tests a bunch of the
// correctness of heloGetter() in rules.go.
var heloTests = []struct {
	helo, match string
}{
	{"127.0.0.1", "helo-has bareip helo-has myip"},
	{"127.0.0.1", "not helo-has properip"},
	{"[127.0.0.1]", "helo-has properip helo-has myip"},
	{"[127.0.0.1]", "not helo-has bareip"},
	{"[192.168.10.3]", "helo-has remip"},
	{"[192.168.10.3]", "not helo-has myip"},
	{"[200.200.200.200]", "helo-has otherip"},
	{"127.10.100.10", "helo-has otherip"},
	{"[192.168.10.]", "not helo-has ip"},
	{"[]", "not helo-has ip"},
	{"192.168.10.", "not helo-has ip"},
	{"", "helo-has none"},
	{"", "helo-has nodots"},
	{"fred", "helo-has nodots"},
	{"fred.jim", "helo-has ehlo not helo-has nodots"},
}

func TestHeloHas(t *testing.T) {
	c := setupContext(t)
	for _, s := range heloTests {
		c.heloname = s.helo
		rules, err := Parse(fmt.Sprintf("accept %s", s.match))
		if err != nil {
			t.Errorf("error parsing: %s\n\t%v\n", s.match, err)
			continue
		}
		if !rules[0].check(c) {
			t.Errorf("HELO '%s' does not match: %s\n", s.helo,
				s.match)
		}
	}

	// Test recognition of HELO vs EHLO. We've already tested
	// 'helo-has ehlo' above, as smtpd.EHLO is the default helocmd
	// in our context.
	c.helocmd = smtpd.HELO
	c.heloname = "fred.jim"
	rules, err := Parse("accept helo-has helo")
	if err != nil {
		t.Fatalf("error parsing HELO recognition test: %s", err)
	}
	if !rules[0].check(c) {
		t.Errorf("helo-has did not see this as a 'HELO' helo vs EHLO\n")
	}
}

// Test specific parse failures.
// none of these lines should parse
// note that these are split on \n and each line is then parsed
// separately (because the parser normally stops on the first error),
// so you can't do line-continuation tests here.
var notParse = `helo
accept dns fred,barney
accept dns nodns, good
accept fred
accept host jones or
accept (host jones or)
accept host jones or barney
accept source
accept
accept not
accept not fred
accept not dns fred
accept host
accept ( host james
accept ( )
accept ip abcdef
accept ip ip
accept tls fred
accept or host fred
accept host fred or dns fred
accept dnsbl file:/a/somewhere
accept dnsbl host
accept dnsbl has-no-dots
accept all with
accept all with message
accept all with message fred message
accept all with message fred message barney
accept all with note fred note barney
accept all with savedir fred savedir barney
accept with message fred
accept all with note "embedded newline
	is here"
set-with all
set-with all with note a;
set-with all with ;
set-with all with note a; all
set-with all with tls-opt yes
set-with all with tls-opt
@from accept to @fbi.gov`

func TestNotParse(t *testing.T) {
	for _, ln := range strings.Split(notParse, "\n") {
		rules, err := Parse(ln)
		if err == nil {
			t.Errorf("rule did not error out: '%s'\n\t%+v\n", ln, rules)
		}
	}
}

// Test DNS blocklist checks based on our artificial DNS blocklist cache
// entries set up in setupContext().
func TestDnsblHit(t *testing.T) {
	c := setupContext(t)
	rules, _ := Parse("accept dnsbl nosuch.domain")
	if !rules[0].check(c) {
		t.Fatalf("did not hit in nosuch.domain")
	}
	if len(c.dnsblhit) != 1 && c.dnsblhit[0] != "nosuch.domain" {
		t.Fatalf("did not list nosuch.domain in c.dnsblhit:\n\t%v\n", c.dnsblhit)
	}
	c.dnsblhit = []string{}
	rules, _ = Parse("accept dnsbl notthere.domi")
	if rules[0].check(c) {
		t.Fatalf("did hit for notthere.domi")
	}
	if len(c.dnsblhit) != 0 {
		t.Fatalf("c.dnsblhit is not empty after notthere.domi test:\n\t%v\n", c.dnsblhit)
	}
}

// Test 'with' option setting, both for set-with and for the actual matching
// rule (which should override a set-with value).
var aWiths = `set-with all with message fred note joe
accept all with savedir bob note jim tls-opt off
`
var resVals = []struct{ k, v string }{
	{"message", "fred"}, {"savedir", "bob"}, {"note", "jim"},
	{"tls-opt", "off"},
}

func TestWithSetting(t *testing.T) {
	c := setupContext(t)
	rules, err := Parse(aWiths)
	if err != nil {
		t.Fatalf("error parsing:\n%s\nerror: %v", aWiths, err)
	}
	for _, r := range rules {
		res := r.check(c)
		if !res {
			t.Fatalf("rule %s did not match", r)
		}
	}
	for _, e := range resVals {
		if c.withprops[e.k] != e.v {
			t.Errorf("with property difference: for %s expected %s got '%s'", e.k, e.v, c.withprops[e.k])
		}
	}
}
