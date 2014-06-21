//
// Right now this merely tests some support functions in rules.go and
// does not attempt to test the main Decide() function. That one is
// complicated, especially if we want to test the full logic; we'd
// have to construct some rules and then drive an entire conversation
// through Decide().

package main

import (
	"testing"
)

//
// Test address and host matches, since so much depends on them.
var aMatches = []struct {
	a, pat string
}{
	{"abc@def", "abc@def"},
	{"", "<>"},
	{"abc@def", "abc@"},
	{"abc@def", "@def"},
	{"abc", "abc@"},
	{"abc@def.ghi", "@.ghi"},
	{"abc@def.ghi", "@.def.ghi"},
	{"anything@anything", "@"},
}
var nMatches = []struct {
	a, pat string
}{
	{"abc@def", "not"},
	{"abc@def", "@ghi"},
	{"abc@def", "def@"},
	{"anything", "<>"},
	{"noat", "@"},
	{"abc@zamdef.ghi", "@.def.ghi"},
	{"", "@"},
	{"@route", "@"},
	{"broken@", "@"},
}

func TestAddrMatches(t *testing.T) {
	for _, inp := range aMatches {
		if !matchAddress(inp.a, inp.pat) {
			t.Errorf("did not match '%s' with pattern '%s'", inp.a, inp.pat)
		}
	}
	for _, inp := range nMatches {
		if matchAddress(inp.a, inp.pat) {
			t.Errorf("did match '%s' with pattern '%s'", inp.a, inp.pat)
		}
	}
}

// Hostname matching tests
var ahMatches = []struct {
	h, pat string
}{
	{"abc", "abc"},
	{"abc", ".abc"},
	{"abc.def", ".def"},
	{"abc.def.ghi", ".ghi"},
}
var nhMatches = []struct {
	h, pat string
}{
	{"abc", "not"},
	{"abc", ".not"},
	{"prefabc", ".abc"},
}

func TestHostMatches(t *testing.T) {
	for _, inp := range ahMatches {
		if !matchHost(inp.h, inp.pat) {
			t.Errorf("did not match '%s' with pattern '%s'", inp.h, inp.pat)
		}
	}
	for _, inp := range nhMatches {
		if matchHost(inp.h, inp.pat) {
			t.Errorf("did match '%s' with pattern '%s'", inp.h, inp.pat)
		}
	}
}

// Tests for thing -> options set for it functions in rules.go.
// Note that rparse_test.py also does a certain amount of implicit
// testing as part of its general match testing.

// Test whether various addresses yield various address options that they
// should. This is not an exhaustive test of all possibilities, especially
// of all of the various garbage addresses.
var aOpts = []struct {
	addr string
	opt  Option
}{
	{"", oZero},
	{"noat", oNoat},
	{"\"fred\"@jones", oQuoted | oUnqualified},
	{"jim@jones", oUnqualified},
	{"@jones:user@jim.bob", oRoute},
	{"@j:user@jim", oRoute | oUnqualified},
	{"@garbage", oGarbage | oUnqualified},
	{"garbage@", oGarbage | oUnqualified},
	{"<job@jim.bob", oGarbage},
	{"joe..@jim.bob", oGarbage},
	{"joe@@jim.bob", oGarbage},
	{"joe@jim.bob\"", oGarbage},
	{"joe@jim.bob>", oGarbage},
	// Ideally this wouldn't happen, but oh well
	{"\"joe..bob\"@jim.bob", oQuoted | oGarbage},
}

func TestAddrOpts(t *testing.T) {
	for _, opt := range aOpts {
		o := getAddrOpts(opt.addr)
		if o != opt.opt {
			t.Errorf("address '%s' evaluated to: %v instead of %v\n", opt.addr, o, opt.opt)
		}
	}
}

// Test generation of DNS options for a given set of DNS results.
// We simply fake the contents of context.trans.rdns because we
// know that dnsGetter() just looks at list length.
// We borrow setupContext() from rparse_test.go.
var dOpts = []struct {
	ver, nofw, inc bool
	opt            Option
}{
	{true, false, false, oGood | oExists},
	{false, true, false, oNofwd | oNodns},
	{false, false, true, oInconsist | oNodns},
	{false, false, false, oNodns},
	{true, true, true, oExists | oNofwd | oInconsist},
	{false, true, true, oNodns | oNofwd | oInconsist},
}

func TestDnsOpts(t *testing.T) {
	var s = []string{"a.c"}
	var choose = func(v bool) []string {
		if v {
			return s
		}
		return []string{}
	}
	c := setupContext(t)
	for _, opt := range dOpts {
		c.trans.rdns.verified = choose(opt.ver)
		c.trans.rdns.nofwd = choose(opt.nofw)
		c.trans.rdns.inconsist = choose(opt.inc)
		o := dnsGetter(c)
		if o != opt.opt {
			t.Errorf("dns %v/%v/%v evaluated to: %v instead of %v\n", opt.ver, opt.nofw, opt.inc, o, opt.opt)
		}
	}
}
