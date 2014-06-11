sinksmtp: cmd/sinksmtp.go cmd/tlsnames.go smtpd.go cmd/rdns.go cmd/rlex.go cmd/rnodes.go cmd/rparse.go cmd/rules.go
	cd cmd && go build -o ../sinksmtp

clean:
	rm -f sinksmtp
