// SIP client

static const char __attribute__((unused)) * TAG = "SIP";

#include "revk.h"
#include "sip.h"

// Register as client, returns 0 on error, else number of seconds until near expiry (i.e. when should register again)
uint32_t sip_register(const char *server, const char *username,const char *password,sip_rtp_tx_t *rx)
{
	// TODO
	return 0;
}

// Make a call, response is 200 if worked, else the call error code
uint32_t sip_register(const char *server, const char *uri, const char *username,const char *password,sip_rtp_tx_t *rx)
{
	// TODO
	return 0;
}

