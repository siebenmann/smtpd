sinksmtp: cmd/sinksmtp.go cmd/tlsnames.go smtpd.go cmd/rdns.go
	go build cmd/sinksmtp.go cmd/tlsnames.go cmd/rdns.go

clean:
	rm -f sinksmtp
