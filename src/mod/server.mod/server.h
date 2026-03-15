/*
 * server.h -- part of server.mod
 */
/*
 * Copyright (C) 1997 Robey Pointer
 * Copyright (C) 1999 - 2025 Eggheads Development Team
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _EGG_MOD_SERVER_SERVER_H
#define _EGG_MOD_SERVER_SERVER_H

#define CAPMAX           499    /*  (512 - "CAP REQ :XXX\r\n")     */
#define CLITAGMAX        4096   /* Max size for IRCv3 message-tags sent by client*/
#define TOTALTAGMAX      8191   /* @ + Server tag len + ; + Client tag len + ' ' */
#define MSGMAX           511    /* Max size of IRC message line    */
#define SENDLINEMAX      CLITAGMAX + MSGMAX
#define RECVLINEMAX      TOTALTAGMAX + MSGMAX
#define NEWSERVERMAX     256
#define NEWSERVERPASSMAX 128

#define check_tcl_ctcp(a,b,c,d,e,f) check_tcl_ctcpr(a,b,c,d,e,f,H_ctcp)
#define check_tcl_ctcr(a,b,c,d,e,f) check_tcl_ctcpr(a,b,c,d,e,f,H_ctcr)

#ifndef MAKING_SERVER
/* 4 - 7 */
/* Empty */
#define botuserhost ((char *)(server_funcs[5]))
#ifdef TLS
#define use_ssl (*(int *)(server_funcs[6]))
#else
/* Was quiet_reject (moved to core) <Wcc[01/21/03]>. */
#endif
#define serv (*(int *)(server_funcs[7]))
/* 8 - 11 */
#define flud_thr (*(int*)(server_funcs[8]))
#define flud_time (*(int*)(server_funcs[9]))
#define flud_ctcp_thr (*(int*)(server_funcs[10]))
#define flud_ctcp_time (*(int*)(server_funcs[11]))
/* 12 - 15 */
#define match_my_nick ((int(*)(char *))server_funcs[12])
#define check_tcl_flud ((int (*)(char *,char *,struct userrec *,char *,char *))server_funcs[13])
/* Empty, formally msgtag */
#define answer_ctcp (*(int *)(server_funcs[15]))
/* 16 - 19 */
#define trigger_on_ignore (*(int *)(server_funcs[16]))
#define check_tcl_ctcpr ((int(*)(char*,char*,struct userrec*,char*,char*,char*,p_tcl_bind_list))server_funcs[17])
/* Was detect_avalanche */
#define nuke_server ((void(*)(char *))server_funcs[19])
/* 20 - 23 */
#define newserver ((char *)(server_funcs[20]))
#define newserverport (*(int *)(server_funcs[21]))
#define newserverpass ((char *)(server_funcs[22]))
#define cycle_time (*(int *)(server_funcs[23]))
/* 24 - 27 */
#define default_port (*(int *)(server_funcs[24]))
#define server_online (*(int *)(server_funcs[25]))
#define H_rawt (*(p_tcl_bind_list *)(server_funcs[26]))
#define H_raw (*(p_tcl_bind_list *)(server_funcs[27]))
/* 28 - 31 */
#define H_wall (*(p_tcl_bind_list *)(server_funcs[28]))
#define H_msg (*(p_tcl_bind_list *)(server_funcs[29]))
#define H_msgm (*(p_tcl_bind_list *)(server_funcs[30]))
#define H_notc (*(p_tcl_bind_list *)(server_funcs[31]))
/* 32 - 35 */
#define H_flud (*(p_tcl_bind_list *)(server_funcs[32]))
#define H_ctcp (*(p_tcl_bind_list *)(server_funcs[33]))
#define H_ctcr (*(p_tcl_bind_list *)(server_funcs[34]))
#define ctcp_reply ((char *)(server_funcs[35]))
/* 36 - 39 */
#define get_altbotnick ((char *(*)(void))(server_funcs[36]))
#define nick_len (*(int *)(server_funcs[37]))
#define check_tcl_notc ((int (*)(char *,char *,struct userrec *,char *,char *))server_funcs[38])
#define exclusive_binds (*(int *)(server_funcs[39]))
/* 40 - 43 */
#define H_out (*(p_tcl_bind_list *)(server_funcs[40]))
#define net_type_int (*(int *)(server_funcs[41]))
/* #define H_account unused */
#define cap (*(capability_t **)(server_funcs[43]))
/* 44 - 47 */
#define extended_join (*(int *)(server_funcs[44]))
#define account_notify (*(int *)(server_funcs[45]))
#define H_isupport (*(p_tcl_bind_list *)(server_funcs[46]))
#define isupport_get ((struct isupport *(*)(const char *, size_t))(server_funcs[47]))
/* 48 - 51 */
#define isupport_parseint ((int (*)(const char *, const char *, int, int, int, int, int *))(server_funcs[48]))
/* #define check_tcl_account NULL */
#define find_capability ((struct capability *(*)(char *))(server_funcs[50]))
#define encode_msgtags ((char *(*)(Tcl_Obj *))(server_funcs[51]))
/* 52 - 55 */
#define H_monitor (*(p_tcl_bind_list *)(server_funcs[52]))
#define isupport_get_prefixchars ((const char *(*)(void))server_funcs[53])
#define H_stdreply (*(p_tcl_bind_list *)(server_funcs[54]))


#endif /* MAKING_SERVER */

struct server_list {
  struct server_list *next;

  char *name;
  int port;
#ifdef TLS
  int ssl;
#endif
  char *pass;
  char *realname;
};

/* struct to store values associated with a capability, such as "PLAIN" and
 * "EXTERNAL" for SASL
 */
typedef struct cap_values {
  struct cap_values *next;
  char name[CAPMAX];
} cap_values_t;

typedef struct capability {
  struct capability *next;
  char name[CAPMAX+1];  /* Name of capability, +1 bc CAPMAX is for REQ not LS */
  struct cap_values *value; /* List of values associated with the capability  */
  int enabled;      /* Is the capability currently negotiated with the server */
  int requested;    /* Does Eggdrop  want this capability, if available?      */
} capability_t;

typedef struct monitor_list {
  char nick[NICKLEN];         /* List of nicks to monitor,                */
  int online;                 /* Flag if nickname is currently online     */
  struct monitor_list *next;  /* Linked list y'all                        */
} monitor_list_t;

/* Available net types. */
enum {
  NETT_DALNET,       /* DALnet                            */
  NETT_EFNET,        /* EFnet                             */
  NETT_FREENODE,     /* freenode                          */
  NETT_HYBRID_EFNET, /* Hybrid-6+ EFnet +e/+I/max-bans 20 */
  NETT_IRCNET,       /* IRCnet                            */
  NETT_LIBERA,       /* Libera Chat                       */
  NETT_QUAKENET,     /* QuakeNet                          */
  NETT_RIZON,        /* Rizon                             */
  NETT_UNDERNET,     /* UnderNet                          */
  NETT_TWITCH,       /* Twitch! *shudder*                 */
  NETT_OPHION,       /* Ophion/IRCX extended network      */
  NETT_OTHER         /* Others                            */
};

/* =========================================================================
 * IRCX (Internet Relay Chat eXtended) Protocol Support
 * Compatible with Ophion IRC server (https://github.com/devinkbrown/ophion)
 * ========================================================================= */

/* IRCX server reply numerics */
#define RPL_IRCX          800   /* Server supports IRCX                    */
#define RPL_PROPS         801   /* Property listing reply                  */
#define RPL_ENDOFPROPS    802   /* End of property list                    */
#define RPL_ACCESSLIST    803   /* Access list entry                       */
#define RPL_ENDOFACCESS   804   /* End of access list                      */
#define ERR_NOTIRCX       901   /* Client not in IRCX mode                 */
#define ERR_ALREADYIRCX   902   /* Already in IRCX mode                    */
#define ERR_UNKNOWNPROP   903   /* Unknown property name                   */
#define ERR_PROPDENIED    904   /* Property access denied                  */
#define ERR_PROPFULL      905   /* Property list full                      */
#define ERR_NOACCESS      906   /* Insufficient access level               */

/* IRCX access levels (matching ophion m_ircx_access.c hierarchy) */
#define IRCX_ACCESS_DENY    "DENY"    /* Denies channel access              */
#define IRCX_ACCESS_GRANT   "GRANT"   /* Grants access (overrides ban)      */
#define IRCX_ACCESS_QUIET   "QUIET"   /* Suppress messages from user        */
#define IRCX_ACCESS_VOICE   "VOICE"   /* Auto-voice on join (+v)            */
#define IRCX_ACCESS_HOST    "HOST"    /* Channel host / operator (+o)       */
#define IRCX_ACCESS_OWNER   "OWNER"   /* Channel owner (+q)                 */

/* IRCX mode characters for owner/admin (ophion extensions) */
#define IRCX_MODE_OWNER   'q'         /* Owner mode  (+q)                   */
#define IRCX_MODE_ADMIN   'a'         /* Admin mode  (+a) on some servers   */

/* Built-in IRCX channel property names (ophion m_ircx_prop_channel_builtins) */
#define IRCX_PROP_OID         "OID"         /* Unique channel ID (read-only)  */
#define IRCX_PROP_NAME        "NAME"        /* Channel name (read-only)       */
#define IRCX_PROP_CREATION    "CREATION"    /* Creation timestamp (read-only) */
#define IRCX_PROP_TOPIC       "TOPIC"       /* Channel topic                  */
#define IRCX_PROP_MEMBERCOUNT "MEMBERCOUNT" /* Member count (read-only)       */
#define IRCX_PROP_MEMBERKEY   "MEMBERKEY"   /* Channel join key (+k mode)     */
#define IRCX_PROP_MEMBERLIMIT "MEMBERLIMIT" /* Member limit (+l mode)         */
#define IRCX_PROP_OWNERKEY    "OWNERKEY"    /* Key granting owner (+q) on join*/
#define IRCX_PROP_OPKEY       "OPKEY"       /* Key granting op (+o) on join   */
#define IRCX_PROP_PICS        "PICS"        /* Content rating string          */
#define IRCX_PROP_LAG         "LAG"         /* Per-channel message delay (s)  */
#define IRCX_PROP_CLIENT      "CLIENT"      /* Client metadata (ops only)     */

/* IRCX channel prefix for persistent/registered channels */
#define IRCX_CHAN_PERSISTENT '%'

/* IRCX access list entry - stored per channel.
 * Uses fixed-size arrays to remain includable from all modules. */
typedef struct ircx_access_entry {
  struct ircx_access_entry *next;
  char channel[201];                /* Channel this entry applies to (CHANNELLEN+1) */
  char mask[512];                   /* Nick!user@host mask or account name  */
  char level[16];                   /* OWNER / HOST / VOICE / GRANT / DENY  */
  char setter[33];                  /* Handle that set this entry (HANDLEN+1) */
  time_t set_time;                  /* Unix timestamp when set              */
} ircx_access_t;

/* IRCX auto-owner entry - channels where bot requests owner on join */
typedef struct ircx_autoowner_entry {
  struct ircx_autoowner_entry *next;
  char channel[201];                /* Channel name (with prefix, CHANNELLEN+1) */
  char ownerkey[128];               /* OWNERKEY value sent on join          */
  int  create_if_missing;           /* Use IRCX CREATE if channel is empty  */
  char create_modes[32];            /* Modes applied after CREATE           */
} ircx_autoowner_t;

#endif /* _EGG_MOD_SERVER_SERVER_H */
