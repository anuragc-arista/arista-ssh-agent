## What is this?

This is a proof-of-concept for single-use certificate generation as part of SSH
authentication.

Do not use this implementation. I cut some corners and it is not suitable for
production use. It was merely made to showcase an idea.

## How to use?

The CA cert and key used for this PoC was pregenerated; if you'd like to
generate new ones, run `make clean` then `make`.

Setup your local ssh daemon by copying the generated CA public key and telling
sshd to trust it:

```console
$ sudo cp ca.pub /etc/ssh/ca.pub
$ sudo chmod 600 /etc/ssh/ca.pub
$ echo 'TrustedUserCAKeys /etc/ssh/ca.pub' | sudo tee -a /etc/ssh/sshd_config
```

Start or restart sshd.

To run the agent, simply execute the following command:

```
$ go run .
```

This will create a socket named agent.sock in the current directory.

In another terminal, try using the agent to connect to localhost:

```
$ SSH_AUTH_SOCK=$(pwd)/agent.sock ssh localhost -vvv
```

If you did the setup correctly, you should now be logged in.
