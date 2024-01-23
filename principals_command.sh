#!/bin/bash
#
# principals_command.sh %u %i
# %u The username / %i The key ID in the certificate.

user="$1"
keyId="$2"

# ssh user certificates obtained through vault's google auth method contain
# a principal in the username@arista.com format. We need to append @arista.com
# to the authorized principal this script outputs when using google auth for it
# to match the principal in the ssh user certificate. Otherwise, we won't be
# able to login using google auth.

if [[ $keyId = *"google"* ]] && [ "${user}" != "arastra" ]; then
    user="$user@arista.com"
fi

echo "$user"
