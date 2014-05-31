//
// A sinkhole SMTP server.
// This accepts things and files them away, or perhaps refuses things for
// you. It can log detailed transactions if desired.
//
// TODO: needs lots of comments.
//

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"smtpd"
	"time"
)

// Time without the timezone.
const TimeNZ = "2006-01-02 15:04:05"

func warnf(format string, elems ...interface{}) {
	fmt.Fprintf(os.Stderr, "sinksmtp: "+format, elems...)
}

// This is used to log the SMTP commands et al for a given SMTP session.
// It encapsulates the prefix. Perhaps we could do this some other way,
// for example with a function closure, but PUNT for now.
type smtpLogger struct {
	prefix []byte
	writer *bufio.Writer
}

func (log *smtpLogger) Write(b []byte) (n int, err error) {
	// MY HEAD HURTS. WHY DOES THIS HAPPEN.
	// ... long story involving implicit casts to interfaces.
	// This safety code is disabled because I want a crash if I screw
	// this up at a higher level. This may be a mistake.
	//if log == nil {
	//	return
	//}

	_, err = log.writer.Write(log.prefix)
	if err != nil {
		return 0, err
	}
	n, err = log.writer.Write(b)
	if err == nil {
		err = log.writer.Flush()
	}
	return n, err
}

type smtpTransaction struct {
	raddr, laddr net.Addr
	heloname     string
	from         string
	rcptto       []string

	data string
	hash string    // canonical hash of the data, currently SHA1
	when time.Time // when the DATA was received.

	tlson  bool
	cipher uint16
}

func msgDetails(prefix string, trans *smtpTransaction, embedbody bool) []byte {
	var outbuf bytes.Buffer
	writer := bufio.NewWriter(&outbuf)
	fmt.Fprintf(writer, "id %s %s\n", prefix, trans.when.Format(TimeNZ))
	fmt.Fprintf(writer, "remote %v to %v with helo '%s'\n", trans.raddr,
		trans.laddr, trans.heloname)
	if trans.tlson {
		fmt.Fprintf(writer, "tls on cipher 0x%04x\n", trans.cipher)
	}
	fmt.Fprintf(writer, "from <%s>\n", trans.from)
	for _, a := range trans.rcptto {
		fmt.Fprintf(writer, "to <%s>\n", a)
	}
	fmt.Fprintf(writer, "hash %s bytes %d\n", trans.hash, len(trans.data))
	if embedbody {
		fmt.Fprintf(writer, "body\n%s", trans.data)
	}
	writer.Flush()
	return outbuf.Bytes()
}

func logMessage(prefix string, trans *smtpTransaction, logf io.Writer) {
	if logf == nil {
		return
	}
	var outbuf bytes.Buffer
	writer := bufio.NewWriter(&outbuf)
	fmt.Fprintf(writer, "%s [%s] from %v / ",
		trans.when.Format(TimeNZ), prefix,
		trans.raddr)
	fmt.Fprintf(writer, "<%s> to", trans.from)
	for _, a := range trans.rcptto {
		fmt.Fprintf(writer, " <%s>", a)
	}
	fmt.Fprintf(writer, ": message %d bytes hash %s | local %v helo '%s'",
		len(trans.data), trans.hash, trans.laddr, trans.heloname)
	if trans.tlson {
		fmt.Fprintf(writer, " tls:cipher 0x%04x", trans.cipher)
	}
	fmt.Fprintf(writer, "\n")
	writer.Flush()
	logf.Write(outbuf.Bytes())
}

func handleMessage(prefix string, trans *smtpTransaction, logf io.Writer) (string, error) {
	var hash string
	logMessage(prefix, trans, logf)
	if savedir == "" {
		return trans.hash, nil
	}
	// ... always include message for now.
	m := msgDetails(prefix, trans, true)
	// This saves one copy of every unique message, using the first
	// set of details.
	if msghash {
		hash = trans.hash
	} else {
		h := sha1.New()
		h.Write(m)
		hash = fmt.Sprintf("%x", h.Sum(nil))
	}
	tgt := savedir + "/" + hash
	fp, err := os.OpenFile(tgt, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0666)
	if err == nil {
		fp.Write(m)
		fp.Close()
	} else {
		if !os.IsExist(err) {
			warnf("error writing message file: %v\n", err)
		} else {
			err = nil
		}
	}
	return hash, err
}

func process(cid int, nc net.Conn, tlsc tls.Config, logf io.Writer, smtplog io.Writer) {
	var evt smtpd.EventInfo
	var convo *smtpd.Conn
	var l2 io.Writer

	trans := &smtpTransaction{}
	trans.raddr = nc.RemoteAddr()
	trans.laddr = nc.LocalAddr()
	prefix := fmt.Sprintf("%d/%d", os.Getpid(), cid)

	if smtplog != nil {
		logger := &smtpLogger{}
		logger.prefix = []byte(prefix)
		logger.writer = bufio.NewWriterSize(smtplog, 4096)
		l2 = logger
	}

	sname := trans.laddr.String()
	if srvname != "" {
		sname = srvname
	}
	convo = smtpd.NewConn(nc, sname, l2)
	if goslow {
		convo.AddDelay(time.Second / 10)
	}
	if len(tlsc.Certificates) > 0 {
		tlsc.ServerName = sname
		convo.AddTLS(&tlsc)
	}

	// Main transaction loop. We gather up email messages as they come
	// in, possibly failing various operations as we're told to.
	for {
		evt = convo.Next()
		switch evt.What {
		case smtpd.COMMAND:
			switch evt.Cmd {
			case smtpd.EHLO, smtpd.HELO:
				if failhelo {
					convo.Reject()
					continue
				}
				trans.heloname = evt.Arg
				trans.from = ""
				trans.data = ""
				trans.hash = ""
				trans.rcptto = []string{}
			case smtpd.MAILFROM:
				if failmail {
					convo.Reject()
					continue
				}
				trans.from = evt.Arg
				trans.data = ""
				trans.rcptto = []string{}
			case smtpd.RCPTTO:
				if failrcpt {
					convo.Reject()
					continue
				}
				trans.rcptto = append(trans.rcptto, evt.Arg)
			case smtpd.DATA:
				if faildata {
					convo.Reject()
				}
			}
		case smtpd.GOTDATA:
			// message rejection is deferred until after logging
			// et al.
			trans.data = evt.Arg
			trans.when = time.Now()
			trans.tlson = convo.TLSOn
			trans.cipher = convo.TLSCipher
			h := sha1.New()
			h.Write([]byte(trans.data))
			trans.hash = fmt.Sprintf("%x", h.Sum(nil))
			transid, err := handleMessage(prefix, trans, logf)
			if err == nil {
				if failgotdata {
					convo.RejectData(transid)
				} else {
					convo.AcceptData(transid)
				}
			} else {
				convo.Tempfail()
			}
		}
		if evt.What == smtpd.DONE || evt.What == smtpd.ABORT {
			break
		}
	}
	nc.Close()
}

var failhelo bool
var failmail bool
var failrcpt bool
var faildata bool
var failgotdata bool
var goslow bool
var srvname string
var savedir string
var msghash bool

func openlogfile(fname string) (outf io.Writer, err error) {
	if fname == "" {
		return nil, nil
	}
	if fname == "-" {
		return os.Stdout, nil
	}
	return os.OpenFile(fname,
		os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
}

func main() {
	var smtplogfile, logfile string
	var certfile, keyfile string
	var force bool
	var tlsConfig tls.Config

	flag.BoolVar(&failhelo, "H", false, "reject all HELO/EHLOs")
	flag.BoolVar(&failmail, "F", false, "reject all MAIL FROMs")
	flag.BoolVar(&failrcpt, "T", false, "reject all RCPT TOs")
	flag.BoolVar(&faildata, "D", false, "reject all DATA commands")
	flag.BoolVar(&failgotdata, "M", false, "reject all messages after they're fully received. This rejection is 'fake', as messages may still be logged and/or saved if either is configured.")
	flag.BoolVar(&goslow, "S", false, "send output to the network at one character every tenth of a second")
	flag.StringVar(&srvname, "helo", "", "server name to advertise in greeting banners, defaults to local IP:port of connection")
	flag.StringVar(&smtplogfile, "smtplog", "", "filename for SMTP conversation logs, '-' means standard output, no default")
	flag.StringVar(&logfile, "l", "", "filename of the transaction log, no default")
	flag.StringVar(&savedir, "d", "", "directory to save received messages in")
	flag.BoolVar(&force, "force-receive", false, "force accepting email even without a savedir")
	flag.BoolVar(&msghash, "hash-msg-only", false, "save files under the hash of the message only, not of their full information")
	flag.StringVar(&certfile, "c", "", "TLS PEM certificate file")
	flag.StringVar(&keyfile, "k", "", "TLS PEM key file")

	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: sinksmtp [options] host:port")
		return
	}
	if savedir == "" && !(force || failhelo || failmail || failrcpt || faildata || failgotdata) {
		warnf("I refuse to accept email without either a -d savedir or --force-receive\n")
		return
	}

	switch {
	case certfile != "" && keyfile != "":
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			warnf("error loading TLS cert from %s & %s: %v\n", certfile, keyfile, err)
			return
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.SessionTicketsDisabled = true

	case certfile != "":
		warnf("certfile specified without keyfile")
		return
	case keyfile != "":
		warnf("keyfile specified without certfile")
		return
	}

	conn, err := net.Listen("tcp", flag.Arg(0))
	if err != nil {
		warnf("error listening to tcp!%s: %s\n", flag.Arg(0), err)
		return
	}

	slogf, err := openlogfile(smtplogfile)
	if err != nil {
		warnf("error opening SMTP log file '%s': %v\n", smtplogfile, err)
		return
	}
	logf, err := openlogfile(logfile)
	if err != nil {
		warnf("error opening logfile '%s': %v\n", logfile, err)
		return
	}

	if savedir != "" {
		tstfile := savedir + "/.wecanmake"
		fp, err := os.Create(tstfile)
		if err != nil {
			warnf("cannot create test file in savedir '%s': %v\n", savedir, err)
			return
		}
		fp.Close()
		os.Remove(tstfile)
	}

	cid := 1
	for {
		nc, err := conn.Accept()
		if err == nil {
			go process(cid, nc, tlsConfig, logf, slogf)
		}
		cid += 1
	}
}
