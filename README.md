## What is this?

This is a proof-of-concept for single-use certificate generation as part of SSH
authentication.

It used Vault SSH as the CA for generating the certificates. The only supported
auth method at the time this was written is LDAP.

This implementation is not suitable for production use.

## How to use?

The destination host must have the CA's public key. You need to configure ssh to
trust it. The key can be obtained from: https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key

```bash
$ curl  https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key -o /etc/ssh/vault-ssh-ca-key.pem
$ sudo chmod 644 /etc/ssh/vault-ssh-ca-key.pem
$ echo 'TrustedUserCAKeys /etc/ssh/vault-ssh-ca-key.pem' | sudo tee -a /etc/ssh/sshd_config
```

Restart sshd `sudo systemctl restart sshd`

------------------------------------------

On the client side, this is your laptop. Update the local ssh config to use the custom agent socket and enable
agent forwarding by default.

```bash
$ pwd                                                                      
/Users/jsuarez/repos/ssh-agent-poc

sudo vim sudo vim ~/.ssh/config
```

Add the following configuration:

```
Host *
  ForwardAgent yes
  IdentityAgent /Users/jsuarez/repos/ssh-agent-poc/agent.sock
```

The above will use the config for all hosts, feel free to narrow it down.

------------------------------------------

To run the agent, simply execute the following command:

```bash
$ go run .
```

This will prompt for your LDAP credentials and create a socket named `agent.sock`` in the current directory.

In another terminal, try using the agent to connect to localhost:

```
$ ssh abs104 -vvv
```

If you did the setup correctly, you should now be logged in. If you forwarded the agent you can run `ssh-add -L` to
verify that you are able to get new certs. From here try connecting to another host configured to use the CA.

```bash
~ @abs104.sjc> ssh -A bs337 whoami
~ @abs104.sjc> ssh -A bs337 ssh-add -L
jsuarez
```

Try using et, scp, mosh (Does not support agent forwarding), pdsh or Ansible.
