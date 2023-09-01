package main

/* The following codes are taken from the IETF document
   draft-miller-ssh-agent-00 § 5.2. */

type RequestCode byte

// SSH agent request codes
const (
	SSH_AGENTC_REQUEST_IDENTITIES            RequestCode = 11
	SSH_AGENTC_SIGN_REQUEST                  RequestCode = 13
	SSH_AGENTC_ADD_IDENTITY                  RequestCode = 17
	SSH_AGENTC_REMOVE_IDENTITY               RequestCode = 18
	SSH_AGENTC_REMOVE_ALL_IDENTITIES         RequestCode = 19
	SSH_AGENTC_ADD_ID_CONSTRAINED            RequestCode = 25
	SSH_AGENTC_ADD_SMARTCARD_KEY             RequestCode = 20
	SSH_AGENTC_REMOVE_SMARTCARD_KEY          RequestCode = 21
	SSH_AGENTC_LOCK                          RequestCode = 22
	SSH_AGENTC_UNLOCK                        RequestCode = 23
	SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED RequestCode = 26
	SSH_AGENTC_EXTENSION                     RequestCode = 27
)

type ResponseCode byte

// SSH agent response codes
const (
	SSH_AGENT_FAILURE           ResponseCode = 5
	SSH_AGENT_SUCCESS           ResponseCode = 6
	SSH_AGENT_EXTENSION_FAILURE ResponseCode = 28
	SSH_AGENT_IDENTITIES_ANSWER ResponseCode = 12
	SSH_AGENT_SIGN_RESPONSE     ResponseCode = 14
)

const SSH_CODE_NUM = 29

type SignatureFlag byte

// SSH signature flags
const (
	SSH_AGENT_RSA_SHA2_256 SignatureFlag = 2
	SSH_AGENT_RSA_SHA2_512 SignatureFlag = 4
)
