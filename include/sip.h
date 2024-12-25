// SIP
#include <stdint.h>

#define	SIP_ALAW

#define SIP_RATE        8000
#define	SIP_MS		20
#define	SIP_BYTES	160

#ifdef	SIP_ALAW
#define SIP_CODING      "pcma"
#define SIP_SILENCE     0x55
#define SIP_PT  	8
#endif

#ifdef	SIP_ULAW
#error	No ulaw yet
#endif

// A 16 bit quarter sine table (values 0-65535) at SIP_RATE
extern const uint16_t sip_sin4_8k[];

// A mapping of 7 bit RTP coding (alaw/ulaw) to 13 bit signed PCM 
extern const int16_t sip_rtp_to_pcm13[];

// A mapping of 13 bits signed PCM (i.e. 8192 entries from -4096 to +4095) to RTP coding (alaw/ulaw)
extern const uint8_t sip_pcm13_to_rtp[];

// SIP task related functions (task started automatically)

typedef enum __attribute__((__packed__))
{
   SIP_IDLE,                    // Not registered
      SIP_REGISTERED,           // Idle, but registered for incoming calls
      SIP_IC_ALERT,             // Incoming call is alerting, we can call sip_answer() or sip_hangup()
      SIP_OG_ALERT,             // Outgoing call is alerting, we can call sip_hangup() to cancel
      SIP_IC,                   // Incoming call is active
      SIP_OG,                   // Outgoing call is active
} sip_state_t;

// Audio
// data NULL, len==0    No audio - just state info
// data, len>1          Audio (should be 160 bytes every 20ms, as per #defines above)
// data, len==1         DTMF (code is in one byte in data)
// data, len==0         Special case, data is NULL terminated string

// Called on state change and for incoming audio (data NULL if no audio)
typedef void sip_callback_t (sip_state_t state, uint8_t len, const uint8_t * data);

// Called on tx/rx of SIP
typedef void sip_debug_t (uint8_t rx, struct sockaddr_storage *addr, const char *message);

// Send audio data for active call
int sip_audio (uint8_t len, const uint8_t * data);

// Start sip_task, set up details for registration (can be null if no registration needed)
void sip_register (const char *host, const char *user, const char *pass, sip_callback_t * callback, sip_debug_t * debug);
void sip_dereg(void);	// No longer register

// Set up an outgoing call, proxy optional (taken from uri)
int sip_call (const char *cli, const char *uri, const char *proxy, const char *user, const char *pass);

// Answer a call
int sip_answer (void);

// Hangup, cancel, or reject a call
int sip_hangup (void);
