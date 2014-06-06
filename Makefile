sinksmtp: cmd/sinksmtp.go cmd/tlsnames.go smtpd.go
	go build cmd/sinksmtp.go cmd/tlsnames.go

clean:
	rm -f sinksmtp
