// SIP client

static const char __attribute__((unused)) * TAG = "SIP";

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sip.h"
#include "siptools.h"

TaskHandle_t
make_task (const char *tag, TaskFunction_t t, const void *param, int kstack)
{                               // Make a task
   if (!kstack)
      kstack = 8;               // Default 8k
   TaskHandle_t task_id = NULL;
   xTaskCreate (t, tag, kstack * 1024, (void *) param, 2, &task_id);
   if (!task_id)
      ESP_LOGE (TAG, "Task %s failed", tag);
   return task_id;
}

int
replacestring (char **target, const char *new)
{                               // Replace a string pointer with new value, malloced, returns non zero if changed
   char *old = *target;
   if (new && old && !strcmp (old, new))
      return 0;                 // No change
   if (!new && !old)
      return 0;                 // No change
   if (new)
      *target = strdup (new);
   else
      *target = NULL;
   free (old);
   return 1;
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
      TASK_IG_ALERT,            // We are sending 180
      TASK_IG_BUSY,             // We are sending 486, waiting ACK
      TASK_IG_OK,               // We are sending 200, waiting ACK
      TASK_IG,                  // We are in an incoming call
      TASK_IG_BYE,              // We are sendin BYEs, awaiting reply
} sip_task_state_t;

static struct
{                               // Local data
   TaskHandle_t task;           // Task handle
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
   uint32_t regexpiry;         // Registration expiry
   sip_state_t status;          // Status reported by sip_callback
   uint8_t call:1;		// Outgoing call required
   uint8_t answer:1;            // Answer required
   uint8_t hangup:1;            // Hangup required
} sip = { 0 };

// Generally not very thread safe

// Start sip_task, set up details for registration (can be null if no registration needed)
void
sip_register (const char *host, const char *user, const char *pass, sip_callback_t * callback)
{
   sip.callback = callback;
   if (!sip.task)
      sip.task = make_task ("sip", sip_task, NULL, 8);
   if (replacestring (&sip.ichost, host) + replacestring (&sip.icuser, user) + replacestring (&sip.icpass, pass))
      sip.regexpiry = 0;        // Register
}

// Set up an outgoing call, proxy optional (taken from uri)
int
sip_call (const char *cli, const char *uri, const char *proxy, const char *user, const char *pass)
{
   if (sip.status > SIP_REGISTERED)
      return 1;
   replacestring (&sip.ogcli, cli);
   replacestring (&sip.oghost, proxy);
   replacestring (&sip.oguri, uri);
   replacestring (&sip.oguser, user);
   replacestring (&sip.ogpass, pass);
   sip.call = 1;
   return 0;
}

// Answer a call
int
sip_answer (void)
{
   if (sip.status != SIP_IC_ALERT)
      return 1;
   sip.answer = 1;
   return 0;
}

// Hangup, cancel, or reject a call
int
sip_hangup (void)
{
   if (sip.status <= SIP_REGISTERED)
      return 1;
   sip.hangup = 1;
   return 0;
}

static void
sip_task (void *arg)
{
   sip_task_state_t state;
   // Set up sockets

   make_task ("sip-audio", sip_audio_task, NULL, 8);
   // Main loop
   while (1)
   {
      sleep (1);


      // TODO
   }
}

static void
sip_audio_task (void *arg)
{
   // Set up sockets

   // Main loop
   while (1)
   {
      sleep (1);
      // TODO
   }
}

// Send audio data for active call
void
sip_audio (uint8_t len, const uint8_t * data)
{
   // TODO
}
