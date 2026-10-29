/* Copyright (c) 2026 Rai Technology.  All rights reserved.
 *  http://www.raitechnology.com
 *
 * natsapi.h -- thread-safe NATS consumer / publisher api, shaped like the
 * tibrv 7 api that sassrv/rv7api.h provides for RV and omm/ommapi.h for OMM
 * (same queue / event / transport model, so a program written for one maps
 * onto the others and raimdapi wraps all three the same way):
 *
 *   nats_Open()                         start the api (one epoll thread)
 *   natsTransport_Create( &t, &parms )  connect to a NATS server (CONNECT
 *                                       with name / user / pass / token)
 *   natsQueue_Create( &q )              an event queue the app thread drains
 *   natsEvent_CreateListener( &e, q, t, "RSF.REC.MSFT.N", 0, cb, cl )
 *                                       a subscription; the subject may be
 *                                       a NATS wildcard (A.*.C, A.>)
 *   natsEvent_CreateTimer( &e, q, cb, secs, cl )
 *   natsQueue_TimedDispatch( q, secs )  run callbacks on this thread
 *   natsTransport_Send( t, subject, reply, data, len, enc )   publish
 *
 * Design points, where this differs from ommapi.h:
 *
 *  - NATS has no source directory and no dictionary service, so the omm
 *    directory calls (GetSourceCount / GetSource / MatchSubject /
 *    HaveDictionary) do not exist here.  A subject is any NATS subject; a
 *    sass dictionary, when wanted, is fetched by the application the way
 *    natsmd_client does it (publish to _TIC.REPLY.SASS.DATA.DICTIONARY with
 *    an inbox reply, see natsTransport_CreateInbox()).
 *  - A message is a raw NATS payload with the sassrv subject schema (RVMSG,
 *    TIBMSG, TIB_SASS, JSON, ... whatever the publisher wrote); there is no
 *    stream state.  The listener / message semantics follow rv7api: a
 *    listener on a subject or wildcard, each message delivered with its
 *    subject, reply, payload bytes and the codec id raimd detects for the
 *    bytes (natsMsg_GetMsgEnc(), 0 when unknown).
 *  - NATS clients publish, so there is natsTransport_Send() (bytes) and
 *    natsTransport_SendMsg() (a natsMsg built with natsMsg_Create() /
 *    natsMsg_SetData(), or a received one forwarded).  Payloads larger than
 *    the server's max_payload are fragmented and reassembled by the
 *    underlying EvNatsClient, transparently to the api.
 *  - The CONNECT is sent with echo:false, a transport never receives its
 *    own publishes.
 *  - Several listeners may share a subject (one SUB to the server); NATS
 *    sends one copy per matching subscription, so a subject covered by
 *    both an exact listener and a wildcard listener (or by overlapping
 *    wildcards) arrives once per distinct subscription; the api collapses
 *    those consecutive copies so each listener sees the message once.
 *  - A NATS queue group may be named per subject with
 *    natsEvent_CreateQueueListener(); it applies to the first listener on
 *    the subject, later listeners share its subscription.
 *  - Reconnect: a transport retries every reconnect_secs after a
 *    disconnect / failed connect and re-subscribes every live listener;
 *    state changes go to the natsTransport_SetStateListener() queue as
 *    NATS_MSG_TRANSPORT_UP / _DOWN messages.
 *
 * A message is valid for the duration of the callback unless
 * natsMsg_Detach() is called.  Every call may be made from any thread.
 * Status codes are nats_status; natsStatus_GetText() describes them.
 *
 * Not in v1: blocking request / reply (natsTransport_SendRequest), NATS
 * headers (HPUB / HMSG), JetStream. */
#ifndef __rai_natsmd__natsapi_h__
#define __rai_natsmd__natsapi_h__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t natsId;
typedef natsId   natsTransport,
                 natsQueue,
                 natsQueueGroup,
                 natsEvent,
                 natsDispatcher,
                 natsDispatchable; /* a queue or a queue group */
typedef struct nats_msg_s * natsMsg;

#define NATS_INVALID_ID      0
#define NATS_DEFAULT_QUEUE   1
#define NATS_WAIT_FOREVER    -1.0
#define NATS_NO_WAIT         0.0
#define NATS_MAX_INBOX_LEN   88 /* _INBOX.<session>.<number> + nul */

typedef enum {
  NATS_OK                  = 0,
  NATS_INIT_FAILURE        = 1,
  NATS_NOT_INITIALIZED     = 2,
  NATS_INVALID_TRANSPORT   = 3,
  NATS_INVALID_QUEUE       = 4,
  NATS_INVALID_QUEUE_GROUP = 5,
  NATS_INVALID_EVENT       = 6,
  NATS_INVALID_DISPATCHER  = 7,
  NATS_INVALID_ARG         = 8,
  NATS_INVALID_SUBJECT     = 9,  /* empty, has spaces / nul, or too long */
  NATS_NOT_CONNECTED       = 11,
  NATS_TIMEOUT             = 12,
  NATS_NOT_SUPPORTED       = 13,
  NATS_NO_MEMORY           = 14,
  NATS_INVALID_MSG         = 15
} nats_status;

/* transport connection parameters (strings are copied) */
typedef struct {
  const char * daemon;       /* host[:port], default 127.0.0.1:4222 */
  const char * name;         /* CONNECT name, default "natsapi" */
  const char * user;         /* CONNECT user, NULL = none */
  const char * password;     /* CONNECT pass */
  const char * auth_token;   /* CONNECT auth_token */
  double       reconnect_secs; /* retry interval after a disconnect,
                                * 0 = default (1s), < 0 = don't reconnect */
  int          advisory;     /* session advisories for a nats-server (not
                              * raims) network: _NATS.<session>.START/STATUS/
                              * STOP, LISTEN.START/STOP, and the subscription
                              * list rpc on _INBOX.<session>.SUBS; 0 = off,
                              * 1 = on with a 90s STATUS, > 1 = STATUS secs */
} natsTransportParams;

/* fill defaults */
void nats_InitTransportParams( natsTransportParams *p );

nats_status  nats_Open( void );
nats_status  nats_Close( void );
const char * nats_Version( void );
const char * natsStatus_GetText( nats_status status );

nats_status natsTransport_Create( natsTransport *tport,
                                  const natsTransportParams *parms );
nats_status natsTransport_Destroy( natsTransport tport );
/* connected = tcp up, INFO received and CONNECT sent */
nats_status natsTransport_IsConnected( natsTransport tport,  int *connected );
/* block until connected or timeout secs (NATS_WAIT_FOREVER) */
nats_status natsTransport_WaitConnected( natsTransport tport,  double timeout );
nats_status natsTransport_GetDaemon( natsTransport tport,  const char **daemon );
nats_status natsTransport_GetName( natsTransport tport,  const char **name );
nats_status natsTransport_GetUser( natsTransport tport,  const char **user );
nats_status natsTransport_SetDescription( natsTransport tport,  const char *d );
nats_status natsTransport_GetDescription( natsTransport tport,  const char **d );
/* the server's max_payload from INFO (0 before connected); larger
 * publishes are fragmented and only reassembled by another natsmd client */
nats_status natsTransport_GetMaxPayload( natsTransport tport,
                                         uint32_t *max_payload );
/* a unique reply subject _INBOX.<session>.<n> for this transport; the
 * transport subscribes _INBOX.<session>.> once connected, so a listener
 * on the inbox subject receives the replies (NATS_NOT_CONNECTED before
 * the first connect, the session is made then) */
nats_status natsTransport_CreateInbox( natsTransport tport,  char *inbox_str,
                                       uint32_t inbox_len );
/* publish len bytes of data on subject with an optional reply subject;
 * msg_enc is the raimd codec id of the bytes (informational, NATS does not
 * carry it); NATS_NOT_CONNECTED when the transport is down */
nats_status natsTransport_Send( natsTransport tport,  const char *subject,
                                const char *reply,  const void *data,
                                uint32_t len,  uint32_t msg_enc );
/* publish a natsMsg: its send subject, reply subject and data */
nats_status natsTransport_SendMsg( natsTransport tport,  natsMsg msg );
/* connection state changes are delivered as events on a queue: the callback
 * gets a msg with natsMsg_GetMsgClass() == NATS_MSG_TRANSPORT_UP / _DOWN and
 * natsMsg_GetStatusText() describing it */
nats_status natsTransport_SetStateListener( natsTransport tport,
                                            natsQueue queue,
                                            void ( *cb )( natsEvent event,
                                                          natsMsg msg,
                                                          void *closure ),
                                            const void *closure,
                                            natsEvent *event );

typedef void ( *natsQueueOnComplete )( natsQueue queue,  void *closure );

nats_status natsQueue_Create( natsQueue *queue );
nats_status natsQueue_Destroy( natsQueue queue );
nats_status natsQueue_DestroyEx( natsQueue queue,  natsQueueOnComplete cb,
                                 const void *closure );
/* dispatch all pending events (waiting up to timeout secs for the first);
 * NATS_TIMEOUT when nothing arrived */
nats_status natsQueue_TimedDispatch( natsQueue queue,  double timeout );
nats_status natsQueue_TimedDispatchOneEvent( natsQueue queue,  double timeout );
nats_status natsQueue_Dispatch( natsQueue queue );   /* wait forever */
nats_status natsQueue_Poll( natsQueue queue );       /* no wait */
nats_status natsQueue_GetCount( natsQueue queue,  uint32_t *num_events );
nats_status natsQueue_SetPriority( natsQueue queue,  uint32_t priority );
nats_status natsQueue_GetPriority( natsQueue queue,  uint32_t *priority );
nats_status natsQueue_SetName( natsQueue queue,  const char *name );
nats_status natsQueue_GetName( natsQueue queue,  const char **name );

nats_status natsQueueGroup_Create( natsQueueGroup *grp );
nats_status natsQueueGroup_Destroy( natsQueueGroup grp );
nats_status natsQueueGroup_Add( natsQueueGroup grp,  natsQueue queue );
nats_status natsQueueGroup_Remove( natsQueueGroup grp,  natsQueue queue );
nats_status natsQueueGroup_TimedDispatch( natsQueueGroup grp,  double timeout );

/* a thread that dispatches a queue or group until destroyed */
nats_status natsDispatcher_Create( natsDispatcher *disp,  natsDispatchable able,
                                   double idle_timeout );
nats_status natsDispatcher_Join( natsDispatcher disp );
nats_status natsDispatcher_Destroy( natsDispatcher disp );
nats_status natsDispatcher_SetName( natsDispatcher disp,  const char *name );
nats_status natsDispatcher_GetName( natsDispatcher disp,  const char **name );

typedef enum {
  NATS_TIMER_EVENT     = 1,
  NATS_LISTEN_EVENT    = 3,
  NATS_TRANSPORT_EVENT = 6  /* state listener */
} natsEventType;

/* listener flags (none defined yet; pass 0) */
#define NATS_LISTEN_DEFAULT 0

typedef void ( *natsEventCallback )( natsEvent event,  natsMsg msg,
                                     void *closure );

/* subscribe subject (or wildcard) on tport, events on queue; the SUB goes
 * out when the transport is connected, a listener created before that is
 * subscribed at connect */
nats_status natsEvent_CreateListener( natsEvent *event,  natsQueue queue,
                                      natsTransport tport,
                                      const char *subject,  int flags,
                                      natsEventCallback cb,
                                      const void *closure );
/* the same, as a member of NATS queue group queue_group (SUB subject
 * queue_group sid): the server delivers each message to one member */
nats_status natsEvent_CreateQueueListener( natsEvent *event,  natsQueue queue,
                                           natsTransport tport,
                                           const char *subject,
                                           const char *queue_group,
                                           int flags,  natsEventCallback cb,
                                           const void *closure );
nats_status natsEvent_CreateTimer( natsEvent *event,  natsQueue queue,
                                   natsEventCallback cb,  double interval,
                                   const void *closure );
nats_status natsEvent_Destroy( natsEvent event );
nats_status natsEvent_GetType( natsEvent event,  natsEventType *type );
nats_status natsEvent_GetQueue( natsEvent event,  natsQueue *queue );
nats_status natsEvent_GetListenerSubject( natsEvent event,
                                          const char **subject );
nats_status natsEvent_GetListenerTransport( natsEvent event,
                                            natsTransport *tport );
nats_status natsEvent_GetTimerInterval( natsEvent event,  double *interval );
nats_status natsEvent_ResetTimerInterval( natsEvent event,  double interval );

/* message classes: a data message from a subscription, or the api's own
 * transport state notifications */
typedef enum {
  NATS_MSG_DATA           = 1,
  NATS_MSG_TRANSPORT_UP   = 100,
  NATS_MSG_TRANSPORT_DOWN = 101
} natsMsgClass;

/* received messages (valid during the callback, or until
 * natsMsg_Destroy() after natsMsg_Detach()) */
nats_status natsMsg_GetSubject( natsMsg msg,  const char **subject );
/* the reply subject, "" when none */
nats_status natsMsg_GetReplySubject( natsMsg msg,  const char **reply );
nats_status natsMsg_GetEvent( natsMsg msg,  natsEvent *event );
nats_status natsMsg_GetClosure( natsMsg msg,  void **closure );
nats_status natsMsg_GetMsgClass( natsMsg msg,  natsMsgClass *msg_class );
nats_status natsMsg_GetStatusText( natsMsg msg,  const char **text );
nats_status natsMsg_GetRecvTime( natsMsg msg,  int64_t *recv_ns );
/* the payload bytes (valid while the msg is) */
nats_status natsMsg_GetData( natsMsg msg,  const void **buf,  uint32_t *len );
/* the raimd codec id of the payload: as set by natsMsg_SetData() for a
 * built msg, detected from the bytes for a received one (RVMSG_TYPE_ID,
 * TIBMSG_TYPE_ID, TIB_SASS_TYPE_ID, JSON_TYPE_ID, ...), 0 when unknown */
nats_status natsMsg_GetMsgEnc( natsMsg msg,  uint32_t *msg_enc );
/* keep the message past the callback; natsMsg_Destroy releases it */
nats_status natsMsg_Detach( natsMsg msg );
nats_status natsMsg_Destroy( natsMsg msg );
/* print the subject line and the decoded payload to fp (stdout when NULL) */
nats_status natsMsg_Print( natsMsg msg,  void *fp );

/* messages built for natsTransport_SendMsg() (owned by the caller,
 * natsMsg_Destroy() releases them; the setters copy their arguments) */
nats_status natsMsg_Create( natsMsg *msg );
nats_status natsMsg_SetSendSubject( natsMsg msg,  const char *subject );
nats_status natsMsg_SetReplySubject( natsMsg msg,  const char *reply );
nats_status natsMsg_SetData( natsMsg msg,  const void *buf,  uint32_t len,
                             uint32_t msg_enc );

#ifdef __cplusplus
}
#endif
#endif
