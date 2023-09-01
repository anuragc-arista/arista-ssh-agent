all: ca.pem

clean:
	rm -f ca.*

ca.pem ca.key ca.sshkey:
	openssl genpkey -algorithm ED25519 > ca.key
	openssl req -nodes -new -x509 -key ca.key -out ca.pem -days 1825 -config openssl-ca.cnf
	sshpk-conv ca.key -t ssh -p > ca.sshkey
	chmod 600 ca.sshkey
	go run conv-ssh.go ca.pem > ca.pub
