
static const char __attribute__((unused)) * TAG = "SIP";

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sip.h"
#include "siptools.h"
#include "mbedtls/md5.h"

#define	SIP_PORT	5060
#define	SIP_RTP		8888
#define	SIP_MAX		1500

extern cstring_t appname;
extern const char revk_id[];
extern cstring_t revk_version;
extern void *mallocspi (size_t);

static TaskHandle_t
make_task (cstring_t tag, TaskFunction_t t, const void *param, int kstack)
{                               // Make a task
   if (!kstack)
      kstack = 8;               // Default 8k
   TaskHandle_t task_id = NULL;
   xTaskCreate (t, tag, kstack * 1024, (void *) param, 2, &task_id);
   if (!task_id)
      ESP_LOGE (TAG, "Task %s failed", tag);
   return task_id;
}

static uint32_t
uptime (void)
{
   return esp_timer_get_time () / 1000000LL ? : 1;
}

static int
store (string_t * target, cstring_t new, cstring_t newe)
{                               // Replace a string pointer with new value, malloced, returns non zero if changed - empty strings are NULL
   if (new && !newe)
      newe = new + strlen (new);
   if (new == newe)
      new = newe = NULL;
   string_t old = *target;
   if (!new && !old)
      return 0;                 // No change
   if (new && old)
   {
      cstring_t a = new,
         b = old;
      while (a < newe && *a == *b)
      {
         a++;
         b++;
      }
      if (a == newe && !*b)
         return 0;              // No change
   }
   if (new)
   {
      string_t a = mallocspi (newe - new + 1);
      memcpy (a, new, newe - new);
      a[newe - new] = 0;
      *target = a;
   } else
      *target = NULL;
   free ((void *) old);
   return 1;
}

static void
zap (string_t * target)
{                               // Zap stored string
   string_t old = *target;
   *target = NULL;
   free (old);
}

static void
make_digest (string_t dig, cstring_t username, cstring_t eusername, cstring_t realm, cstring_t erealm, cstring_t password,
             cstring_t epassword, cstring_t method, cstring_t emethod, cstring_t uri, cstring_t euri, cstring_t nonce,
             cstring_t enonce, cstring_t nc, cstring_t enc, cstring_t cnonce, cstring_t ecnonce, cstring_t qop, cstring_t eqop)
{                               // dig is response and must allow 33 bytes
   unsigned char md5buf[16];
   char a1[33],
     a2[33];
   inline void hex (char *o)
   {
      inline void hex (int i)
      {
         if (i >= 10)
            *o++ = 'a' + i - 10;
         else
            *o++ = i + '0';
      }
      for (int i = 0; i < 16; i++)
      {
         hex (md5buf[i] >> 4);
         hex (md5buf[i] & 0xF);
      }
      *o=0;
   }
   mbedtls_md5_context c;
   mbedtls_md5_init (&c);
   mbedtls_md5_update (&c, (void *) username, eusername - username);
   mbedtls_md5_update (&c, (void *) ":", 1);
   mbedtls_md5_update (&c, (void *) realm, erealm - realm);
   mbedtls_md5_update (&c, (void *) ":", 1);
   mbedtls_md5_update (&c, (void *) password, epassword - password);
   mbedtls_md5_finish (&c, md5buf);
   hex(a1);
   ESP_LOGE(TAG,"A1 %s %.*s:%.*s:%.*s",a1,(int)(eusername-username),username,(int)(erealm-realm),realm,(int)(epassword-password),password);
   mbedtls_md5_init (&c);
   mbedtls_md5_update (&c, (void *) method, emethod - method);
   mbedtls_md5_update (&c, (void *) ":", 1);
   mbedtls_md5_update (&c, (void *) uri, euri - uri);
   mbedtls_md5_finish (&c, md5buf);
   hex(a2);
   ESP_LOGE(TAG,"A2 %s %.*s:%.*s",a2,(int)(emethod-method),method,(int)(euri-uri),uri);
   mbedtls_md5_init (&c);
   mbedtls_md5_update (&c, (void *) a1, 32);
   mbedtls_md5_update (&c, (void *) ":", 1);
   mbedtls_md5_update (&c, (void *) nonce, enonce - nonce);
   if (qop)
   {
      mbedtls_md5_update (&c, (void *) ":", 1);
      mbedtls_md5_update (&c, (void *) nc, enc - nc);
      mbedtls_md5_update (&c, (void *) ":", 1);
      mbedtls_md5_update (&c, (void *) cnonce, ecnonce - cnonce);
      mbedtls_md5_update (&c, (void *) ":", 1);
      mbedtls_md5_update (&c, (void *) qop, eqop - qop);
   }
   mbedtls_md5_update (&c, (void *) ":", 1);
   mbedtls_md5_update (&c, (void *) a2, 32);
   mbedtls_md5_finish (&c, md5buf);
   hex(dig);
   ESP_LOGE(TAG,"D  %s %s:%.*s:%.*s:%.*s:%.*s:%s",dig,a1,(int)(enonce-nonce),nonce,(int)(enc-nc),nc,(int)(ecnonce-cnonce),cnonce,(int)(eqop-qop),qop,a2);
   mbedtls_md5_free (&c);
}

static void sip_task (void *arg);
static void sip_audio_task (void *arg);

typedef enum __attribute__((__packed__))
{
   TASK_IDLE,                   // Not in a call
      TASK_OG_INVITE,           // We are sending INVITEs awaiting any response
      TASK_OG_WAIT,             // We have 1XX and waiting, we will send CANCELs if hangup set
      TASK_OG,                  // We are in an outgoing call
      TASK_OG_BYE,              // We are sending BYEs, awaiting reply
      TASK_IC_ALERT,            // We are sending 180
      TASK_IC_BUSY,             // We are sending 486, waiting ACK
      TASK_IC_OK,               // We are sending 200, waiting ACK
      TASK_IC,                  // We are in an incoming call
      TASK_IC_BYE,              // We are sendin BYEs, awaiting reply
} sip_task_state_t;

static struct
{                               // Local data
   TaskHandle_t task;           // Task handle
   SemaphoreHandle_t mutex;     // Mutex for this structure
   sip_callback_t *callback;    // The registered callback functions
   char *callid;                // Current call ID - we handle only one call at a time
   char *ichost;                // Registration details
   char *icuser;                // Registration details
   char *icpass;                // Registration details
   char *ogcli;                 // Outgoing call details
   char *oghost;                // Outgoing call details
   char *oguri;                 // Outgoing call details
   char *oguser;                // Outgoing call details
   char *ogpass;                // Outgoing call details
   uint32_t regexpiry;          // Registration expiry
   sip_state_t state;           // Status reported by sip_callback
   uint8_t call:1;              // Outgoing call required
   uint8_t answer:1;            // Answer required
   uint8_t hangup:1;            // Hangup required
} sip = { 0 };

static int
gethost (cstring_t name, uint16_t port, struct sockaddr_storage *addr)
{
   int len = 0;
   const struct addrinfo hint = {
      .ai_family = AF_UNSPEC,
      .ai_socktype = SOCK_DGRAM,
      .ai_flags = AI_NUMERICSERV,
   };
   struct addrinfo *res = NULL;
   memset (addr, 0, sizeof (*addr));
   char ports[6];
   sprintf (ports, "%d", port);
   if (!getaddrinfo (name, ports, &hint, &res) && res->ai_addrlen)
   {
      memcpy (addr, res->ai_addr, res->ai_addrlen);
      len = res->ai_addrlen;
   }
   freeaddrinfo (res);
   return len;
}

static void
ourip (char *buf, sa_family_t family)
{
   extern esp_netif_t *sta_netif;
   *buf = 0;
   if (family == AF_INET)
   {
      esp_netif_ip_info_t ip;
      if (!esp_netif_get_ip_info (sta_netif, &ip) && ip.ip.addr)
         sprintf (buf, IPSTR, IP2STR (&ip.ip));
   } else if (family == AF_INET6)
   {
      esp_ip6_addr_t ip;
      if (!esp_netif_get_ip6_global (sta_netif, &ip))
         sprintf (buf, "[" IPV6STR "]", IPV62STR (ip));
   }
}

static char *
sip_request (void *buf, struct sockaddr_storage *addr, socklen_t addrlen, uint8_t cseq, cstring_t method, cstring_t uri,
             uint32_t branch, uint64_t tag)
{                               // make a SIP request
   if (!method || !uri || strlen (uri) > 256)
      return NULL;
   if (!strncmp (uri, "sip:", 4))
      uri += 4;
   char *p = buf,
      *e = buf + SIP_MAX;
   sip_add_text (&p, e, method);
   sip_add_text (&p, e, " sip:");
   sip_add_esc (&p, e, uri);
   sip_add_text (&p, e, " SIP/2.0\r\n");
   if (tag)
   {                            // Via
      char us[42];
      ourip (us, addr->ss_family);
      sip_add_headerf (&p, e, "Via", "SIP/2.0/UDP %s", us);
      char b[100];
      sprintf (b, "z9hG4bK%llu-%lu", tag, branch);
      sip_add_extra (&p, e, "branch", b, NULL, ';', 0, 0);
      sip_add_extra (&p, e, "rport", NULL, NULL, ';', 0, 0);
   }
   char c[50];
   sprintf (c, "%u %s", cseq, method);
   sip_add_header (&p, e, "CSeq", c);
   sip_add_header (&p, e, "Max-Forwards", "10");
   return p;
}

static void
sip_content (char **const p, cstring_t e, cstring_t data)
{                               // Add remaining headers and content
   uint16_t l = 0;
   if (data)
      l = strlen (data);
   sip_add_headerf (p, e, "Content-Length", "%u", l);
   sip_add_headerf (p, e, "User-Agent", "%s-%s", appname, revk_version);
   if (*p < e)
      *(*p)++ = '\r';
   if (*p < e)
      *(*p)++ = '\n';
   if (l && (*p) + l <= e)
   {
      memcpy (*p, data, l);
      (*p) += l;
   }
}


void
sip_auth (string_t buf, string_t * pp, cstring_t e, uint16_t code, cstring_t auth, cstring_t user, cstring_t pass)
{
   if (code == 401)
      sip_add_header (pp, e, "Authorization", "Digest ");
   else if (code == 407)
      sip_add_header (pp, e, "Proxy-Authorization", "Digest ");
   else
      return;
   cstring_t method = buf,
      methode = buf;;
   while (methode < e && isalpha ((int) *(unsigned char *) methode))
      methode++;
   cstring_t euri,
     uri = sip_find_request (buf, e, &euri);
   cstring_t eqop,
     qop = sip_find_comma (auth, NULL, "qop", &eqop);
   char cnonce[17];
   {
      unsigned long long cn;
      esp_fill_random (&cn, sizeof (cn));
      sprintf (cnonce, "%016llX", cn);
   }
#define x(t) cstring_t e##t,t=sip_find_comma(auth,NULL,#t,&e##t);if(t)sip_add_comma(pp,e,#t,t,e##t)
#define qx(t) cstring_t e##t,t=sip_find_comma(auth,NULL,#t,&e##t);if(t)sip_add_comma_quote(pp,e,#t,t,e##t)
   sip_add_comma_quote (pp, e, "username", user, NULL);
   if (!auth || !pass)
      return;
   qx (realm);
   qx (nonce);
   sip_add_comma_quote (pp, e, "uri", uri, euri);
   const char nc[] = "00000001";        // As we do not cache and reuse nonces the nc we send will always be 1 as first use of nonce
   char dig[33];
   make_digest (dig, user, user + strlen (user), realm, erealm, pass, pass + strlen (pass),
                method, methode, uri, euri, nonce, enonce, nc, nc + strlen (nc), cnonce, cnonce + strlen (cnonce), qop, eqop);
   sip_add_comma_quote (pp, e, "response", dig, dig + 32);
   x (algorithm);
   sip_add_comma_quote (pp, e, "cnonce", cnonce, NULL);
   qx (opaque);
   if (qop)
      sip_add_comma (pp, e, "qop", qop, eqop);  // Yes, not quoted in response
   sip_add_comma (pp, e, "nc", nc, NULL);
#undef x
#undef qx
}

// Start sip_task, set up details for registration (can be null if no registration needed)
void
sip_register (cstring_t host, cstring_t user, cstring_t pass, sip_callback_t * callback)
{
   sip.callback = callback;
   if (!sip.task)
   {
      sip.mutex = xSemaphoreCreateBinary ();
      xSemaphoreGive (sip.mutex);
      sip.task = make_task ("sip", sip_task, NULL, 8);
   }
   xSemaphoreTake (sip.mutex, portMAX_DELAY);
   if (store (&sip.ichost, host, NULL) + store (&sip.icuser, user, NULL) + store (&sip.icpass, pass, NULL))
      sip.regexpiry = 0;        // Register
   xSemaphoreGive (sip.mutex);
}

// Set up an outgoing call, proxy optional (taken from uri)
int
sip_call (cstring_t cli, cstring_t uri, cstring_t proxy, cstring_t user, cstring_t pass)
{
   xSemaphoreTake (sip.mutex, portMAX_DELAY);
   if (sip.state <= SIP_REGISTERED)
   {
      store (&sip.ogcli, cli, NULL);
      store (&sip.oghost, proxy, NULL);
      store (&sip.oguri, uri, NULL);
      store (&sip.oguser, user, NULL);
      store (&sip.ogpass, pass, NULL);
      sip.call = 1;
   }
   xSemaphoreGive (sip.mutex);
   return 0;
}

// Answer a call
int
sip_answer (void)
{
   xSemaphoreTake (sip.mutex, portMAX_DELAY);
   if (sip.state == SIP_IC_ALERT)
      sip.answer = 1;
   xSemaphoreGive (sip.mutex);
   return 0;
}

// Hangup, cancel, or reject a call
int
sip_hangup (void)
{
   xSemaphoreTake (sip.mutex, portMAX_DELAY);
   if (sip.state > SIP_REGISTERED)
      sip.hangup = 1;
   xSemaphoreGive (sip.mutex);
   return 0;
}

static void
sip_task (void *arg)
{
   // Set up sockets
   int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP);
   if (sock < 0)
   {
      ESP_LOGE (TAG, "SIP Socket failed");
      vTaskDelete (NULL);
      return;
   }
   struct sockaddr_in dest_addr = {.sin_addr.s_addr = htonl (INADDR_ANY),.sin_family = AF_INET,.sin_port = htons (SIP_PORT)
   };
   if (bind (sock, (struct sockaddr *) &dest_addr, sizeof (dest_addr)))
   {
      ESP_LOGE (TAG, "SIP Bind failed");
      vTaskDelete (NULL);
      return;
   }
   make_task ("sip-audio", sip_audio_task, NULL, 8);
   // Main loop
   sip_task_state_t state = 0;
   uint32_t regretry = 0;       // Uptime for register retry
   uint32_t regbackoff = 0;
   uint64_t regcallid = 0;
   uint64_t regtag = 0;
   uint8_t regseq = 0;
   string_t regauth = NULL;
   uint16_t regcode = 0;
   esp_fill_random (&regcallid, sizeof (regcallid));
   while (1)
   {
      sip_state_t status = sip.state;

      char buf[SIP_MAX];
      int len = 0;
      struct sockaddr_storage addr;
      socklen_t addrlen = 0;

      fd_set r;
      FD_ZERO (&r);
      FD_SET (sock, &r);
      struct timeval t = { 1, 0 };      // Wait 1 second
      if (select (sock + 1, &r, NULL, NULL, &t) > 0)
      {                         // Get packet and process
         addrlen = sizeof (addr);
         len = recvfrom (sock, buf, sizeof (buf) - 1, 0, (struct sockaddr *) &addr, &addrlen);
         if (len > 10)
         {
            ESP_LOGE (TAG, "Rx\n%.*s", len, buf);
            cstring_t e = buf + len;
            if (!strncmp (buf, "SIP/", 4))
            {                   // Response
               char *p = buf + 4;
               while (p < e && *p != ' ')
                  p++;
               if (p < e)
               {
                  int code = 0;
                  p++;
                  while (p < e && isdigit ((int) *(unsigned char *) p))
                     code = code * 10 + *p++ - '0';
                  cstring_t methode,
                    method = sip_find_header (buf, e, "CSeq", NULL, &methode, NULL);
                  if (method)
                  {
                     int seq = 0;
                     while (method < methode && isdigit ((int) *(unsigned char *) method))
                        seq = seq * 10 + *method++ - '0';
                     while (method < methode && *method == ' ')
                        method++;
                     if (methode - method == 8 && !strncasecmp (method, "REGISTER", 8))
                     {          // REGISTER reply
                        if (seq == regseq)
                        {
                           if (code == 401 || code == 407)
                           {
                              cstring_t authe,
                               
                                 auth =
                                 sip_find_header (buf, e, code == 401 ? "WWW-Authenticate" : "Proxy-Authenticate", NULL, &authe,
                                                  NULL);
                              store (&regauth, auth, authe);
                              if (regauth)
                                 regcode = code;
                           } else if (code == 200)
                           {    // Registered
                              // TODO expiry?
				   regbackoff=0;
                           }
                        }
                     } else if (methode - method == 6 && !strncasecmp (method, "INVITE", 6))
                     {          // INVITE reply

                     } else if (methode - method == 6 && !strncasecmp (method, "CANCEL", 6))
                     {          // CANCEL reply

                     } else if (methode - method == 3 && !strncasecmp (method, "BYE", 3))
                     {          // CANCEL reply

                     }
                  }
               }
            } else
            {                   // Request
               cstring_t method = buf,
                  methode = buf;
               while (methode < e && isalpha ((int) *(unsigned char *) methode))
                  methode++;
               if (methode - method == 6 && !strncasecmp (method, "INVITE", 6))
               {                // INVITE

               } else if (methode - method == 6 && !strncasecmp (method, "CANCEL", 6))
               {                // CANCEL
               } else if (methode - method == 3 && !strncasecmp (method, "BYE", 3))
               {                // BYE

               }
            }
         }
         continue;
      }

      uint32_t now = uptime ();

      // Do registration logic
      if (sip.regexpiry < now)
         sip.regexpiry = 0;     // Actually expired
      if (sip.regexpiry < now + 60 && sip.ichost && regretry < now)
      {
         cstring_t host = sip.ichost;
         if (!strncmp (host, "sip:", 4))
            host += 4;
         cstring_t local = host;
         cstring_t locale = strchr (local, '@');
         if (locale)
            host = locale + 1;
         else
         {
            local = sip.icuser;
            locale = local + strlen (local);
         }
         if (!(addrlen = gethost (sip.ichost, SIP_PORT, &addr)))
            ESP_LOGE (TAG, "Failed to lookup %s", sip.ichost);
         else
         {                      // Send registration
            esp_fill_random (&regtag, sizeof (regtag));
            if (!regtag)
               regtag = 1;
            regseq++;
            char *e = buf + SIP_MAX;
            char *p = sip_request (buf, &addr, addrlen, regseq, "REGISTER", sip.ichost, 0, regtag);
            if (p)
            {
               char us[42];
               ourip (us, addr.ss_family);
               sip_add_header_angle (&p, e, "From", local, locale, us, NULL);
               sip_add_header_angle (&p, e, "To", local, locale, sip.ichost, NULL);
               sip_add_header_angle (&p, e, "Contact", revk_id, NULL, us, NULL);
               sip_add_headerf (&p, e, "Call-ID", "%llu@%s.%s", regcallid, revk_id, appname);
               sip_add_header (&p, e, "Expires", "3600");
               if (regauth)
                  sip_auth (buf, &p, e, regcode, regauth, sip.icuser, sip.icpass);
               sip_content (&p, (void *) buf + sizeof (buf), NULL);
               sendto (sock, buf, (p - buf), 0, (struct sockaddr *) &addr, addrlen);
               ESP_LOGE (TAG, "Tx\n%.*s", (int) (p - buf), buf);
               regcode = 0;
               zap (&regauth);
            }
         }
         if (!regbackoff)
            regbackoff = 1;
         regretry = now + regbackoff;
         if (regbackoff < 300)
            regbackoff *= 2;
      }
      // TODO giveup logic

      // Do periodic
      switch (state)
      {
      case TASK_IDLE:          // Not in a call
         status = SIP_IDLE;
         if (sip.call)
         {                      // Start outgoing call

            sip.call = 0;
         }
         break;
      case TASK_OG_INVITE:     // We are sending INVITEs awaiting any response
         status = SIP_IDLE;
         break;
      case TASK_OG_WAIT:       // We have 1XX and waiting, we will send CANCELs if hangup set
         status = SIP_OG_ALERT;
         break;
      case TASK_OG:            // We are in an outgoing call
         status = SIP_OG;
         break;
      case TASK_OG_BYE:        // We are sending BYEs, awaiting reply
         status = SIP_IDLE;
         break;
      case TASK_IC_ALERT:      // We are sending 180
         status = SIP_IC_ALERT;
         break;
      case TASK_IC_BUSY:       // We are sending 486, waiting ACK
         status = SIP_IDLE;
         break;
      case TASK_IC_OK:         // We are sending 200, waiting ACK
         status = SIP_IC;
         break;
      case TASK_IC:            // We are in an incoming call
         status = SIP_IC;
         break;
      case TASK_IC_BYE:        // We are sendin BYEs, awaiting reply
         status = SIP_IDLE;
         break;
      }

      // Report status change
      if (status == SIP_IDLE && sip.regexpiry)
         status = SIP_REGISTERED;
      if (status == SIP_REGISTERED && !sip.regexpiry)
         status = SIP_IDLE;
      if (status <= SIP_REGISTERED)
         sip.answer = sip.hangup = 0;
      if (sip.state != status && sip.callback)
         sip.callback (sip.state = status, 0, NULL);
   }
}

static void
sip_audio_task (void *arg)
{
   // Set up sockets
   int sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_IP);
   if (sock < 0)
   {
      ESP_LOGE (TAG, "RTP Socket failed");
      vTaskDelete (NULL);
      return;
   }
   struct sockaddr_in dest_addr = {.sin_addr.s_addr = htonl (INADDR_ANY),.sin_family = AF_INET,.sin_port = htons (SIP_RTP)
   };
   if (bind (sock, (struct sockaddr *) &dest_addr, sizeof (dest_addr)))
   {
      ESP_LOGE (TAG, "RTP Bind failed");
      vTaskDelete (NULL);
      return;
   }
   while (1)
   {
      uint8_t buf[SIP_MAX];
      struct sockaddr_storage source_addr;
      socklen_t socklen = sizeof (source_addr);
      int res = recvfrom (sock, buf, sizeof (buf) - 1, 0, (struct sockaddr *) &source_addr, &socklen);
      ESP_LOGE (TAG, "RTP %d", res);
   }
}

// Send audio data for active call
int
sip_audio (uint8_t len, const uint8_t * data)
{
   // TODO
   return 0;
}
