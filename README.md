## What is this?

This is a proof-of-concept for single-use certificate generation as part of SSH authentication.

The PoC uses **Vault SSH** as the CA for generating the certificates. The only supported auth methods at the time this was
written are **Google**, **OneLogin** and **LDAP**.

**IMPORTANT:** This implementation is not suitable for production use.

## Project Documentation
- [Certificate based SSH Authentication Functional Specification](https://docs.google.com/document/d/1mihzMojfbmt5vqQwn5Gal5KXnLutbHrhLAkrEYhdK8Q/edit#heading=h.rf1hab8253ep)
- [Certificate based SSH Authentication Design Specification](https://docs.google.com/document/d/1E_PlOtrYHJOUPJoBA763mSGausAcQ5TCehiM81VJPyE/edit?pli=1#heading=h.rjubebvvumoq)

## How to use?

There are 3 main steps to follow:
- 1. Configure the ssh client (workstation/laptop).
- 2. Run the arista ssh-agent.
- 3. Configure the destination host (optional).

For convenience we have a test server already configured `bs337`,
you might skip step #3 unless you need to configure an additional server. In the case were you want to configure an
additional host, we have an ansible playbook for that, reach out and we can setup the server for you or show you how to
run the playbook. We will include manual instructions in this guide.

### Client Configuration

On the client side, this is your laptop/workstation, we need to add a config block to your local ssh config. The config
block will:
- Enable agent forwarding ([ForwardAgent](https://man.openbsd.org/ssh_config.5#ForwardAgent))
- Point your ssh client to the arista ssh-agent UNIX-domain socket ([IdentityAgent](https://man.openbsd.org/ssh_config.5#IdentityAgent))
- Force the use of ssh certificates, we are using the `ssh-ed25519-cert-v01@openssh.com` signature ([PubKeyAcceptedAlgorithms](https://man.openbsd.org/ssh_config.5#PubkeyAcceptedAlgorithms))
- Disable password authentication ([PasswordAuthentication](https://man.openbsd.org/ssh_config.5#PasswordAuthentication) and [KbdInteractiveAuthentication](https://man.openbsd.org/ssh_config.5#KbdInteractiveAuthentication))

```
sudo vim ~/.ssh/config
```

**IMPORTANT:** The `agent.sock` socket file will be created where the ssh-agent-poc binary is ran. Please update the `IdentityAgent` value in
the configuration below as needed.

Add the following configuration:

```bash
Host bs337
  ForwardAgent yes
  IdentityAgent /Users/<user>/go/src/ssh-agent-poc/agent.sock
  PubKeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com
  PasswordAuthentication no
  KbdInteractiveAuthentication no

```

The above configuration can be used after the next step by running `ssh bs337`. Feel free to expand it to more hosts.

**Note:** Only use the `ForwardAgent yes` option by default for **home-buses**, **a4c workspaces** or **user servers**.
The following configuration directives are **optional** and will not be necessary when the servers are automatically
configured. We will block the use of `AuthorizedKeysFile` and disable password authentication on the host end.
- `PubKeyAcceptedAlgorithms`, `PasswordAuthentication` and `KbdInteractiveAuthentication` 

### Running the arista ssh-agent

To run the agent, simply execute the following command from the root of the repository:

```bash
go run .
```

Optionally, specify the login provider (`-p`), options are `google`(default), `onelogin` and `ldap`.
E.g. to use OneLogin:

```bash
go run . -p onelogin
```

This will start an `oidc` browser based login flow or it will prompt for your `LDAP` credentials. The ssh-agent socket
named `agent.sock` will be created in the current directory and ready to be used.

In another terminal, try using the agent to connect to `bs337`:

```bash
ssh bs337 -vvv
```

If you did the setup correctly, you should now be logged in. From here try connecting to another host you configured to
use ssh certificates. Try using `et`, `scp`, `mosh` (Does not support agent forwarding on buses, see details below),
`pdsh` or `Ansible`.

If you forwarded the agent you can run `ssh-add -L` to verify that `bs337` is able to get new certs from the arista
ssh-agent running on your workstation.

### Inspecting the certificate on the host's end (Agent forwarding must be enabled)

Another way to verify the socket is being forwarded and that certificates can be generated by the agent running on your
workstation on `bs337`, run the following from your workstation:

```bash
ssh bs337 ssh-add -L
```
To inspect a certificate to see your principals, extensions, etc. You can run:

```bash
ssh bs337 ssh-add -L | ssh-keygen -Lf -
```

**Note:** You can also run `sh-add -L` and `ssh-add -L | ssh-keygen -Lf -` directly on the host.

### Inspecting the certificate on the client's end (workstation)

If you want the ssh client to interact with the arista ssh-agent socket to inspect a certificate we need to tell the
client the location of the UNIX socket:

```bash
SSH_AUTH_SOCK=/Users/jsuarez/repos/ssh-agent-poc/agent.sock ssh-add -L | ssh-keygen -Lf -
```

## Manual host configuration (Optional)

**IMPORTANT:** You must have a local account on the host or have `sssd` configured.

If configuring a server to trust the CA, you need to update `sshd_config` and save the CA's public key on the host.
The key can be obtained from:
- https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key
- https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh-ol/public_key

On the host were you want to configure the CA trusted key, first save the public CA keys to the host:

```bash
curl -sS https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh/public_key -o /etc/ssh/vault-ssh-ca-key.pem
curl -sS https://vault.aristanetworks.com:8200/v1/anet/engprod/ssh-ol/public_key >> /etc/ssh/vault-ssh-ca-key.pem
sudo chmod 0644 /etc/ssh/vault-ssh-ca-key.pem
```

Add the `AuthorizedPrincipalsCommand` script:

```bash
sudo vim /usr/bin/principals_command.sh
```

The script is located in the root of the repository (`principals_command.sh`)

Update file permissions:

```bash
sudo chmod 0755 /usr/bin/principals_command.sh
```

Update `sshd_config` on the host:

```bash
sudo tee -a /etc/ssh/sshd_config <<EOF
# SSH CA Configuration
# This is the CA's public key, for authenticating user certificates:
TrustedUserCAKeys /etc/ssh/ssh-ca-key.pem
AuthorizedPrincipalsCommand /usr/bin/principals_command.sh %u %i
AuthorizedPrincipalsCommandUser nobody
EOF
```

You can verify the `sshd_config` config by running:

```bash
sudo sshd -T
```

If the verification did not fail, it should be safe to restart sshd (This will not kill existing sessions)

```bash
sudo systemctl restart sshd
```

## Mosh Support

Mosh does not support ssh-agent forwarding. See this [issue](https://github.com/mobile-shell/mosh/issues/120). We have a
workaround for this limitation (**not applicable to buses**). We are able to get ssh-agent forwarding working by using
`multiplexing` and the mosh `--experimental-remote-ip=remote` flag. The option `--experimental-remote-ip=remote` is
necessary as mosh disables `controlmaster` in its init script by passing `-S None`.

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

We need to keep the above connection open as that's where the ssh-agent communication will flow trough. We can now go
ahead and connect using mosh:

```bash
mosh --experimental-remote-ip=remote user@host
```

Do a quick test to fetch a cert from your workstation:

```bash
ssh-add -L | ssh-keygen -Lf -
```

### Mosh Troubleshooting

If your `ssh` connection drops the ssh-agent communication will break, to fix this you can re-establish the ssh
connection and then exit and re-connect the mosh session. If you don't want to exit the mosh session you can update the
value of your `SSH_AUTH_SOCK` env variable to that of the ssh session. For more detail check https://bb/873687
