/*
Sinksmtp is a sinkhole SMTP server. It accepts things and files them
away, or perhaps refuses things for you. It can log detailed transactions
if desired. Messages are received in all 8 bits, although we don't
advertise 8BITMIME.

usage: sinksmtp [options] [host]:port [[host]:port ...]

Note that sinksmtp never exits. You must kill it by hand to shut
it down.

Main options

This attempts to group options together logically.

	-helo NAME
		Hostname to advertise in our greeting banner. If not
		set, we first try to look up the DNS name of the local
		IP of the connection, then just use the local 'IP:port'
		(which always exists). If DNS returns multiple names,
		we use the first.

	-S	Slow; send all server replies out to the network at a rate
		of one character every tenth of a second.

	-c FILE, -k FILE
		Provide TLS certificate and private key to enable TLS.
		Both files must be PEM encoded. Self-signed is fine.
		You must give both options together (or neither).

	-l FILE
		Log one line per fully received message to this file,
		may be '-' for standard output.

	-smtplog FILE
		Log SMTP commands received and server output (and some
		additional info) to this file. May be '-' for stdout.

	-d DIR
		Save received messages to this directory; received files
		will be given probably-unique hash-based names. May be
		combined with -M, in which case messages will be logged
		then refused.  If there already is a file with the same
		hash-based name, we deliberately don't save over top of
		it (and don't generate any errors). You probably want
		-l too. The saved data includes message metadata.
	-save-hash TYPE
		Base the hash name on one of three things. See 'Save
		file hash naming' later. Valid types are 'msg', 'full',
		and 'all'.
	-force-receive
		Accept email messages even without a -d (or a -M).

	-M	Always send a 5xx rejection after email messages are
		received (post-DATA). This rejection is 'fake' in that
		message details may be logged and messages may be saved
		if -l and/or -d is set.

	-r FILE[,FILE2,...]
		Use FILE et al as control rules files. Rules in
		earlier files take priority over rules in later
		files. For a description of what can be in control
		rules, see the 'Control rules' section.  Explicitly
		set command line options such as -M or the convenience
		options below take priority over rules.

	-dncount NUM
		Start stalling a do-nothing client after this many
		connections in which it did not even EHLO successfully.
		Stalled clients get 4xx responses to everything and
		their SMTP sessions aren't logged. Only does something
		with -smtplog.
	-dndur DUR
		Both how long we stall a do-nothing client for before
		giving it a second chance and the time window over which
		we count do-nothing sessions.
	-minphase PHASE
		The minimum SMTP phase that a client must succeed at in
		order to not be considered a do-nothing client. One of
		helo/ehlo, from, to, data, message, or accepted. 'message'
		means that the client successfully sent us a message,
		even if we then reject it; 'accepted' is a sent message
		that is accepted.

Convenience options

There are also some convenience options for common rule needs.
These are:
	-fromreject FILE
		Reject any MAIL FROM that matches something in this
		address list file.
	-toaccept FILE
		Only accept RCPT TO addresses that match something in
		this address list file (if it exists and is non-empty).
	-heloreject FILE
		Reject any EHLO/HELO name that matches something in in
		this host list file.

NOTE: the filenames here should not have funny characters in them
such as whitespace or commas; otherwise you'll probably get internal
errors or at least odd actions.

Address and hostname lists are reloaded from scratch every time we
start a new connection. It is valid for them to not exist or to have
no entries; this is the same as not specifying one at all (ie, we
accept everything). They are matched as all lower case. See 'Control
rules' for a discussion of what address and hostname patterns are.

Internally these options are compiled into control rules and
then checked before any rules in -r files, as is -M. See later
for a description of what those rules are.

Information in log entries and save files

The format of this information is hopefully obvious.
In save files, everything up to and including the 'body' line is
message metadata (ie all '<name> ...' lines, with lower-case
<name>s); the actual message starts below 'body'. A 'tls' line
will only appear if the message was received over TLS. The cipher
numbers are in octal because that is all net/tls gives us and I
have not yet built a mapping. 'bodyhash ...' may not actually be
a hash for sufficiently mangled messages.
The ID that is printed in a number of places is composed of the
the daemon's PID plus a sequence number of connections that this
daemon has handled; this is to hopefully let you disentangle
multiple simultaneous connections in eg SMTP command logs.

'remote-dns' is the fully verified reverse DNS lookup results, ie
only reverse DNS names that include the remote IP as one of their
IP addresses in a forward lookup. 'remote-dns-nofwd' is reverse
DNS results that did not have a successful forward lookup;
'remote-dns-inconsist' is names that looked up but don't have the
remote IP listed as one of their IPs. Some or all may be missing
depending on DNS lookup results.

TLS

Go only supports SSLv3+ and sinksmtp attempts to validate any client
certificate that clients present to us. Both can cause TLS setup to
fail (yes, there are apparently some MTAs that only support SSLv2).
When TLS setup fails we remember the client IP and don't offer TLS to
it if it reconnects within a certain amount of time (currently 72 hours).

Save file hash naming

With -d DIR set up, sinksmtp saves messages under a hash name computed
for them. There are three possible hash names and 'all' is the default:

'msg' uses only the email contents themselves (the DATA) and doesn't
include metadata like MAIL FROM/RCPT TO/etc, which must be recovered
from the message log (-l). This requires -l to be set.

'full' adds metadata about the message to the hash (everything except
what appears on the 'id' line). If senders improperly resend messages
despite a 5xx rejection after the DATA is transmitted, this should
result in you saving only one copy of each fully unique message.

'all' adds all metadata, including the log ID and timestamp down to the
second.  It will basically always be completely unique (well, assuming
no hash collisions in SHA1 and the sender doesn't send two copies over
the same connection in the same second; this is impossible if you use
-S).

CONTROL RULES

In addition to its command line options for controlling what gets
accepted and rejected when, sinksmtp also lets you give it files of
rules. Rules let you describe things like:

	reject from info@fbi.gov to joe@example.com

This rejects a RCPT TO of 'joe@example.com' if the MAIL FROM was
'info@fbi.gov'.

Rule files and everything they refer to are loaded and parsed at each
new connection. See later for what happens if there is an error.

The simple general form of a rule is:
	[PHASE] ACTION MATCH-OP [MATCH-OP....] ['with' WITH-OPTS]

The action is one of 'accept', 'reject', 'stall' (which emits SMTP 4xx
temporary failure messages), or 'set-with' (which simply sets with
options). The optional phase says that the rule should only be checked
and take effect in that phase of the SMTP transaction and is one of:

	@helo @from @to @data @message

@data is when the DATA command is received but before the sender has
been authorized to send the message; @message is after the message has
been received.

There is also a compact form for checking multiple rule clauses (with
optional with clauses) at once. This separates rule clauses and their
with's with ';' (possibly with a newline immediately after it). For
example:

	set-with helo somehost with message "That's nice";
		 from a@b with message "from a@b" ;
		 from @b with message "from @b"

Such a compact form must end with a rule without a ';' at the end.  In
compact form, each rule clause is checked in order and the first
matching one stops further checking, even (or especially) in set-with
clauses. Compact form rules are probably most useful with set-with.

Most match operations take an argument, as seen.  Match operators can
be negated with 'not':

	reject not from info@fbi.gov to joe@example.com

Anything to joe@example.com that is not from info@fbi.gov will be
rejected.

The default behavior of a series of match operations is that all
of them must match in order for the rule to apply. This can be
changed with the 'or' operator:

	reject from info@fbi.gov to joe@example.com or jim@example.org

Or binds more tightly than a plain series of match operators, so this
means:
	reject from info@fbi.gov (to joe@example.com or jim@example.org)

As seen here, rules can have ( ... ) to change the ordering or just to
be clear about grouping.

Long rule lines can be continued with a ' \' at the end of the line,
eg:
	@message reject (from info@fbi.gov or from @.mil or from bounce@) \
		 to fred@example.net not host trusted.host

The rule file can have blank lines and comment lines, which start with
'#':
	# this is a comment
	@data reject all

Rules allow quoted strings, ".. .. ...". Within a quoted string, a
quote can be escaped with a backslash. Eg:

	reject helo "very \" bogus"

Quoted strings can continue over multiple lines. No '\ ' is needed.
A quoted string cannot be used as a match operator, even if you are
just putting quotes around a match operator, eg the following is
an error:

	reject "helo" .local


It is an error to specify a 'set-with' rule that has no 'with ...'
options. Since such a rule is pointless it's assumed to be a mistake.

The order of rule checking

Eligible rules are checked in order and the first non 'set-with' rule
that matches determines the results. A matching 'set-with' rule
doesn't stop matching, it simply sets (default) with options. These
options can be overridden by a later 'set-with' rule or by the actual
matching rule.

Note especially that this means set-with rule order matters and the
last matching set-with rule for a particular with option is what
controls what that option is set to. For example:

	set-with from @a.b with message "Hi there"
	set-with all with message "You are here"

This will set the SMTP success, failure, or stall message to 'You are
here' even for a MAIL FROM with a domain of a.b, because the 'all'
rule comes after the from-restricted rule. If this is not what you
want, use set-with in compact form:

	set-with from @a.b with message "Hi there";
		 all with message "You are here".

Since this stops checking at the first match, for a MAIL FROM with a
domain of a.b the message will be "Hi there". Note that this rule
cannot be checked before MAIL FROM time because it checks 'from'.
This may be a bug. Compact-form set-withs are probably best used to
set savedir in an easy to follow way in the face of multiple
conditions that may overlap.

When rules are checked

If a rule doesn't have a phase set, it's normally checked at any time
where it's applicable and where all of the information it needs is
available. A rule that does things with MAIL FROM addresses will not
match before @from; a rule that does things with RCPT TO addresses will
not match before @to (and thus can't be used to, say, reject a MAIL
FROM). It is an error to specify an explicit phase that is before all
of the requirements for the rule, ie the following is an error:

	@from reject to joe@example.com

Note that this has significant implications for 'accept' rules.
An unrestricted 'accept' rule will start matching when all of the
information it needs becomes available *and then keep matching again
and again*. Consider a situation where your first rule is:

	accept host .friend.com

This doesn't just accept an EHLO/HELO from your friend; it goes on to
accept MAIL FROM, RCPT TO, DATA, and then the message itself, because
this accept rule is checked in all of those phases too and it's going
to succeed (since it already has). There are two solutions to this;
you can put all accept rules at the end of the rules, or you can put
an explicit phase on the accept rule, eg:

	@helo accept host .friend.com

A rule with an explicit phase (even the phase that it normally requires)
is only checked in that phase.

This issue can also happen with 'stall' or 'reject' rules, but only in
a slightly different situation. Consider the set of rules:

	@helo accept helo liar.com
	reject host .enemy.org

The if an enemy.org host HELOs with 'liar.com', the accept rule will
accept it in HELO and then when it sends a MAIL FROM the reject rule
will match and refuse it.

If you have only reject or stall rules this can't come up because a
matching stall or reject rule prevents the conversation from moving
forward anyways. If you reject at EHLO time, the SMTP conversation will
never send a valid MAIL FROM to be checked.

Match operators and their arguments

Most but not all match operators take arguments. These will be
described later.

 all			always matches

 from APAT, to APAT	match MAIL FROM or RCPT TO respectively
			against address pattern APAT, to be
			discussed later.

			Note that 'to APAT' checks *the current*
			RCPT TO address, not all of the accumulated
			RCPT TO addresses so far. A rule that
			specifies 'to a@b to c@d' will never match.

 helo HPAT		match the name the client gave in its
			HELO/EHLO against the hostname pattern HPAT,
			to be discussed later.
 ehlo HPAT		this is a synonym for 'helo HPAT'. Chris
			added it because he kept making this
			particular mistake.

 host HPAT		match the verified hostname of the remote IP
			(if one exists) against the hostname pattern
			HPAT. The hostname is obtained (and verified)
			through DNS. An IP can have multiple valid
			hostnames; if it does, the HPAT is checked
			against each of them and 'host' succeeds
			if any match.

 ip IP|CIDR|FILENAME	match the remote IP against the given IP
			address or CIDR netblock. If given a
			filename, we read IP addresses and CIDR
			netblocks from the file ala address and
			hostname patterns.

 dnsbl DOMAIN		true if the remote IP is in the given DNS
			blocklist (with any IP address).

 tls on|off		match if TLS is on or off respectively on
			the connection. This doesn't match before
			MAIL FROM right now, because clients
			initially connect in the clear, EHLO once to
			find out if they can start TLS, start TLS,
			and then EHLO again.  We don't know for
			more or less sure if a client is or isn't
			going to do TLS until MAIL FROM time.

 from-has AATTRS, to-has AATTRS
			The MAIL FROM or RCPT TO address has
			at least one of the address attributes
			AATTRS. AATTRS is a comma-separated list
			of specific options.

 helo-has HATTRS	The EHLO/HELO command and its value has at
			least one of the HELO attributes HATTRS, a
			comma separated etc etc.
 dns DATTRS		Reverse DNS for the remote IP has at least
			one of these attributes; a comma separated
			list.


Address and hostname patterns

Address and hostname patterns are more commonly used, so I'll talk
about them first. Both address and hostname patterns can either be a
single pattern or a filename. Filenames are recognized in three forms:
'/a/file', './relative/file', or 'file:<whatever-path>'. Filenames are
expected to have one pattern per line and can contain both blank lines
and comment lines, which start with '#'.  Like rules files, every
address/hostname pattern file is loaded anew for every new connection.

Address patterns and addresses are both lower-cased before being
checked against each other. It's conventional to write them in
all lower case for clarity.

Address patterns themselves can be several things:
	<>		matches 'MAIL FROM:<>', the null sender address.
			It can never match a to address because those do
			not allow null addresses.
	a@b		does a literal match against the address
	a@		matches the local portion 'a' at any domain.
			this will also match eg 'RCPT TO:<a>', ie no
			domain specified in the address.
	@b		matches any local portion at the domain 'b'.
			Note that it doesn't match subdomains, eg 'c.b'.
	@.b.com		matches the domain 'b.com' and any subdomains of it,
			eg 'c.b.com' or 'd.c.b.com'.
	@		matches any address with a local part and a domain.
			in practice this is generally 'any address'.

An address that starts or ends with an '@' will not be matched by any
address pattern here. It's probably broken and in any case sinksmtp
doesn't understand it well enough to match it. Such addresses can be
rejected through other means; see 'from-has' and 'to-has' and address
attributes.

A hostname pattern is either of the things that can appear on the
domain side of an address pattern, that is to say either 'b.com'
(matches literally) or '.b.com' (matches b.com and any subdomains).
As with address patterns, hostnames and hostname patterns are both
lower cased before comparisons.

The files for 'ip file:<whatever>' are parsed the same and act
the same as files for address and hostname patterns; they simply
contain IP addresses or CIDRs instead of address or hostname
patterns.

Behavior of empty rule data files

An empty or missing file causes any rule using it to not match all (as
does an IO error while reading the file). As a result, the rule:

	accept from /no/such/file

will never match anything. The technicality is that this only applies
if the match operator is checked, which it may not be if something else
causes the rule to fail (or succeed) earlier. Thus the following rule
will never care that the file doesn't exist:

	accept all or from /no/such/file

Attributes of addresses et al

AATTRS is one or more of:
	route	address appears to be a route address.
	noat	address has no '@' in it, ie 'MAIL FROM:<aname>'.
	quoted	address has a '"' in it, typically as a quoted local
		part:
			MAIL FROM:<"fred@bob"@example.org>
		This is typically done only by spammers.
	unqualified
		The apparent domain (if any) of the address doesn't
		have a '.' in it, ie:
			MAIL FROM:<fred@localname>
	garbage
		The address just seems to be garbled garbage. Sinksmtp
		can't really tell anything more about it.

	bad	bad is equivalent to 'noat,quoted,unqualified,garbage',
		ie everything except 'route'.

sinksmtp is somewhat casual about determining whether or not an address
really has these attributes; basically it looks for characters in the
address or at certain positions in the address instead of formally
parsing it.

DATTRS is one or more of:
	nodns		remote IP has no verified hostnames
	noforward	remote IP has PTR entries for names that don't
			exist (or at least, don't resolve to IP addresses)
	inconsistent	remote IP has PTR entries for names that exist
			but don't have the remote IP as one of their IP
			addresses.

	exists		remote IP has at least one verified hostname,
			ie 'not dns nodns'.

	good		remote IP has good DNS, ie
				not dns nodns,noforward,inconsistent

Under normal circumstances you probably don't care about noforward
or inconsistent.

A hostname is verified if its listed IP addresses include the IP
address, ie looking up the name for 192.168.1.1 gives 'example.org'
and one of example.org's IP addresses is 192.168.1.1. Invalid
hostnames are not trustworthy because they can be forged by someone
who has control over only the IP to name mapping.

HATTRS is one or more of:
	none		There was no EHLO/HELO name give, just 'EHLO'.
			This can't match right now because sinksmtp
			itself rejects such names.
	helo		The client used the 'HELO' command instead of 'EHLO'
	ehlo		The client used 'EHLO' instead of 'HELO'
	nodots		The HELO name doesn't have any dots in it (and
			technically we allow a : instead), ie it is just
			'EHLO fred' instead of 'EHLO fred.whatever'.
	bareip		The HELO name appears to be just a bare IP address,
			eg 'HELO 127.0.0.1' (instead of 'HELO [127.0.0.1]').
	properip	The HELO name is a proper IP literal, eg
			'[127.0.0.1]'

	myip		The HELO name is the local IP address of the
			server, either bare or in proper form.
	remoteip	The HELO name is the IP address of client,
			either bare or in proper form.
	otherip		The HELO name is in the form of an IP address
			that is neither the local IP nor the client's
			IP. As before, the HELO name may be either
			a bare IP or an IP in proper form.

	ip		The HELO name is an IP address, either bare or
			properly quoted. Ie this is 'bareip,properip'.

With options

A rule can be suffixed with 'with ....' to set some options for when
the rule matches. The following options are supported:

	message MESSAGE
		Use MESSAGE instead of the default message on
		rejections or stalls. If MESSAGE is a multi-line
		quoted string, the SMTP reply will be a properly done
		up multi-line message. MESSAGE cannot currently be a
		file.

	note NOTE
		Write a note to the SMTP log when this rule matches.
		NOTE cannot contain newlines.

	savedir DIR
		Set the directory to save the message in, overriding
		the supplied value for -d (if there is any). It's
		valid to set savedir on a rule without a -d on the
		command line.

For example:

	reject dnsbl sbl.spamhaus.org with message "You're SBL listed."

For technical reasons, 'message' is ineffective for the replies to
HELO and EHLO SMTP commands.

What sinksmtp does when rule loading has errors

If a rules file is missing, has an IO error, or has a parse error,
sinksmtp switches to giving 4xx responses to everything, which in
practice means EHLO/HELO commands (since other commands are invalid
before a successful EHLO or HELO). An error message about the
situation will be logged to standard error. Sinksmtp attempts to log
each error message only once even when there are a bunch of
connections during the time of the bad rule file.

Rules files can be empty. This is not considered an error.

Things to note

Sinksmtp never gives a 5xx or 4xx reply to a 'MAIL FROM:<>',
regardless of what rules you write. If your rules reject or stall this
MAIL FROM, the rejection or stall is deferred until the following RCPT
TOs. This is partly because the RFC says that we aren't allowed to
reject this and partly because I think it's quite likely that client
MTAs will have bad reactions to sinksmtp doing it anyways.

You might wonder what the following does, given that you might have
multiple accepted RCPT TO addresses:
	@data reject to jim@example.com

The answer is basically that it does what you expect. When sinksmtp
receives a DATA command, it checks all accepted RCPT TO addresses and
then rejects the DATA command if any of them are 'jim@example.com'.
The accepted RCPT TO addresses are still checked against the rule one
by one.

That rules can only match when all of the information necessary for
them to be checked is available means that there is an important
difference between:
	reject from-has bad or to-has bad
and
	reject from-has bad
	reject to-has bad

The former rejects due to a bad MAIL FROM address only when the client
does a RCPT TO; because the rule uses 'to-has', it can't be checked at
all until RCPT TO. Since the latter is two rules, they will be checked
separately and the bad MAIL FROM rejected immediately.

How sinksmtp's command line options are implemented

Sinksmtp actually translates all of its what-to-accept options into
rules. These rules are then checked before your rules file, giving
them priority over your rules. Right now, how things translate is:

	# standard rules that are always present
	reject from-has bad,route
	reject to-has bad,route
	reject helo-has none

	# -M
	@message reject all

	# -fromreject
	reject from file:<whatever>
	# -toaccept
	reject not to file:<whatever>
	# -heloreject
	@from reject helo file:<whatever>

Standard -heloreject defers rejecting due to EHLO/HELO until MAIL FROM
time because of my perception that various mailers deal better with this
(ie, they don't expect to have their EHLOs rejected and will sail on or
retry immediately or the like).

The 'stall everything on rules file parse error' behavior is also
implemented with a rule. On such errors, 'stall all' becomes the only
rule that's set up for each connection.

*/
package main
