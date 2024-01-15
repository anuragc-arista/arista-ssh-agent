## What is this?

This is a proof-of-concept for single-use certificate generation as part of SSH authentication.

It uses Vault SSH as the CA for generating the certificates. The only supported auth methods at the time this was
written are Google, OneLogin and LDAP.

This implementation is not suitable for production use.

## How to use?

The destination host must trust the CA's public key. For convenience we have a test server already configured `bs337`.
You can skip this step if you wish.

If configuring a server to trust the CA, you need to configure sshd_config and save the CA's public key on the host.
The key can be obtained from:
- https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key
- https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh-ol/public_key

On the host were you want to configure the CA trusted key:
```bash
$ curl  https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key -o /etc/ssh/vault-ssh-ca-key.pem
$ sudo chmod 644 /etc/ssh/vault-ssh-ca-key.pem
$ echo 'TrustedUserCAKeys /etc/ssh/vault-ssh-ca-key.pem' | sudo tee -a /etc/ssh/sshd_config
```

Restart sshd `sudo systemctl restart sshd`. You can verify the config by running `sudo sshd -T`.

## Client Configuration

On the client side, this is your laptop/workstation. Update the local ssh config to use the arista ssh-agent socket and
enable ssh-agent forwarding by default.

```bash
$ pwd
/Users/jsuarez/repos/ssh-agent-poc

sudo vim ~/.ssh/config
```

Add the following configuration:

```bash
Host bs337
  ForwardAgent yes
  IdentityAgent /Users/jsuarez/repos/ssh-agent-poc/agent.sock
```

The above will add the config to `bs337`, feel free to expand it to more hosts. Only use the sample config by default
for home-buses, a4c workspaces or user servers.

## Running the arista ssh-agent

To run the agent, simply execute the following command:

```bash
$ go run .
```

Optionally, specify the login provider (`-p`), options are `google`(default), `onelogin` and `ldap`.
E.g. to use OneLogin:

```bash
$ go run . -p onelogin
```

This will start an oidc browser based login flow or it will prompt for your LDAP credentials.
A ssh-agent socket named `agent.sock` will be created in the current directory and ready to be used.

In another terminal, try using the agent to connect to `bs337``:

```bash
$ ssh bs337 -vvv
```

If you did the setup correctly, you should now be logged in. If you forwarded the agent you can run `ssh-add -L` to
verify that the host is able to get new certs from the agent on your workstation.

### Extra testing

Another way verify the socket is being forwarded and certificates can be generated by the agent running on your
workstation from `bs337``, run:

```bash
$ ssh bs337 -A ssh-add -L
```
To inspect a cert, you can run:

```bash
ssh bs337 ssh-add -L | ssh-keygen -Lf -
```

You can also run `sh-add -L` and `ssh-add -L | ssh-keygen -Lf -` directly on the host. From here try connecting to
another host you have configured to trust the CA. Try using et, scp, mosh (Does not support agent forwarding on buses,
see details below), pdsh or Ansible.

## Mosh Support

Mosh does not support ssh-agent forwarding. See this [issue](https://github.com/mobile-shell/mosh/issues/120).

We have a workaround for this limitation (**not applicable to buses**). We are able to get ssh-agent forwarding
working by using `multiplexing` and the mosh `--experimental-remote-ip=remote` flag. The option
`--experimental-remote-ip=remote` is necessary as mosh disables `controlmaster` in its init script by passing `-S None`.

We use some openssh directives on the client to enable multiplexing by default:
- https://man.openbsd.org/ssh_config#ControlMaster
- https://man.openbsd.org/ssh_config#ControlPath

You need to add the configuration below to your local ssh config, example:

```bash
Host bs337
  ControlMaster auto
  ControlPath /tmp/control-%h-%p-%r
```

Then you need to start the initial connection used for the agent communication over ssh:

```bash
ssh user@host
```

We need to keep the above connection open as that's were the ssh-agent communication will flow trough. We can now go
ahead and connect using mosh:

```bash
mosh --experimental-remote-ip=remote user@host
```

### Mosh Troubleshooting

If your `ssh` connection drops the ssh-agent communication will break, to fix this you can re-establish the ssh
connection and then exit and re-connect the mosh session. If you don't want to exit the mosh session you can update the
value of your `SSH_AUTH_SOCK` env variable to that of the ssh session. For more detail check https://bb/873687
