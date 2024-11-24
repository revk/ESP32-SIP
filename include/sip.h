
#define SIP_RATE        8000

#ifdef	SIP_ALAW
#define SIP_CODING      "pcma"
#define SIP_RATE        8000
#define SIP_SILENCE     0x55
#define SIP_PT  	8
#endif

#ifdef	SIP_ULAW
#error	No ulaw yet
#endif

// A 16 bit quarter sine table (values 0-65535) at SIP_RATE
extern const int16_t sip_sin4_8k[];

// A mapping of 7 bit RTP coding (alaw/ulaw) to 13 bit signed PCM 
extern const int16_t sip_rtp_to_pcm13[];

// A mapping of 13 bits signed PCM (i.e. 8192 entries from -4096 to +4095) to RTP coding (alaw/ulaw)
extern const uint8_t sip_pcm13_to_rtp[];

// Function call for incoming RTP, a len 0 means end of call
typedef void sip_rtp_rx_t(uint8_t len,const uint8_t *rtp);

// Register as client, returns 0 on error, else number of seconds until near expiry (i.e. when should register again)
extern uint32_t sip_register(const char *server, const char *username,const char *password,sip_rtp_rx_t *rx);

// Make a call, response is 200 if worked, else the call error code
extern uint32_t sip_call(const char *server, const char *uri, const char *username,const char *password,sip_rtp_rx_t *rx);
