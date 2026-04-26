/*
 * chan.h
 *   stuff common to chan.c and mode.c
 *   users.h needs to be loaded too
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

#ifndef _EGG_CHAN_H
#define _EGG_CHAN_H

#include <stdint.h>

/* Valid channel prefixes. */
#define CHANMETA "#&!+"

/* Modes the bot cannot set as halfop. You can add +b, +e, and +I to this to
 * prevent them from being set as halfop. */
#define NOHALFOPS_MODES "ahoq"

/* Only send modes as op (b, e, and I excluded)? */
#undef NO_HALFOP_CHANMODES

/* Hard limit of modes per line. */
constexpr int MODES_PER_LINE_MAX = 6;

#define HALFOP_CANTDOMODE(_a) (!me_op(chan) && (!me_halfop(chan) || (strchr(NOHALFOPS_MODES, _a) != NULL)))
#define HALFOP_CANDOMODE(_a)  (me_op(chan) || (me_halfop(chan) && (strchr(NOHALFOPS_MODES, _a) == NULL)))

typedef struct memstruct {
  char nick[NICKLEN];
  char userhost[UHOSTLEN];
  char account[NICKLEN];
  time_t joined;
  uint64_t flags;
  time_t split; /* in case they were just netsplit */
  time_t last;  /* for measuring idle time         */
  time_t delay; /* for delayed autoop              */
  struct userrec *user; /* cached user lookup */
  int tried_getuser; /* negative user lookup cache */
  struct memstruct *next;
} memberlist;

constexpr uint64_t CHANOP       = 0x00001; /* channel +o                                   */
constexpr uint64_t CHANVOICE    = 0x00002; /* channel +v                                   */
constexpr uint64_t FAKEOP       = 0x00004; /* op'd by server                               */
constexpr uint64_t SENTOP       = 0x00008; /* a mode +o was already sent out for this user */
constexpr uint64_t SENTDEOP     = 0x00010; /* a mode -o was already sent out for this user */
constexpr uint64_t SENTKICK     = 0x00020; /* a kick was already sent out for this user    */
constexpr uint64_t SENTVOICE    = 0x00040; /* a mode +v was already sent out for this user */
constexpr uint64_t SENTDEVOICE  = 0x00080; /* a mode -v was already sent out for this user */
constexpr uint64_t WASOP        = 0x00100; /* was an op before a split                     */
constexpr uint64_t STOPWHO      = 0x00200;
constexpr uint64_t FULL_DELAY   = 0x00400;
constexpr uint64_t STOPCHECK    = 0x00800;
constexpr uint64_t CHANHALFOP   = 0x01000; /* channel +h                                   */
constexpr uint64_t FAKEHALFOP   = 0x02000; /* halfop'd by server                           */
constexpr uint64_t SENTHALFOP   = 0x04000; /* a mode +h was already sent out for this user */
constexpr uint64_t SENTDEHALFOP = 0x08000; /* a mode -h was already sent out for this user */
constexpr uint64_t WASHALFOP    = 0x10000; /* was a halfop before a split                  */
constexpr uint64_t WHO_SYNCED   = 0x20000; /* who reply received for this member           */
constexpr uint64_t IRCAWAY      = 0x40000; /* is marked as away on IRC server              */
constexpr uint64_t IRCBOT       = 0x80000; /* is marked as a bot, per 005/IRCv3 standard   */
/* IRCX / Ophion extended flags */
constexpr uint64_t CHANOWNER    = 0x100000; /* channel +q (IRCX owner mode)               */
constexpr uint64_t SENTOWNER    = 0x200000; /* a mode +q was already sent for this user   */
constexpr uint64_t SENTDEOWNER  = 0x400000; /* a mode -q was already sent for this user   */

#define chan_hasvoice(x)     (x->flags & CHANVOICE)
#define chan_hasop(x)        (x->flags & CHANOP)
#define chan_hashalfop(x)    (x->flags & CHANHALFOP)
#define chan_hasowner(x)     (x->flags & CHANOWNER)  /* IRCX +q owner      */
#define chan_fakeop(x)       (x->flags & FAKEOP)
#define chan_fakehalfop(x)   (x->flags & FAKEHALFOP)
#define chan_sentop(x)       (x->flags & SENTOP)
#define chan_sentdeop(x)     (x->flags & SENTDEOP)
#define chan_senthalfop(x)   (x->flags & SENTHALFOP)
#define chan_sentdehalfop(x) (x->flags & SENTDEHALFOP)
#define chan_sentkick(x)     (x->flags & SENTKICK)
#define chan_sentvoice(x)    (x->flags & SENTVOICE)
#define chan_sentdevoice(x)  (x->flags & SENTDEVOICE)
#define chan_issplit(x)      (x->split > 0)
#define chan_wasop(x)        (x->flags & WASOP)
#define chan_washalfop(x)    (x->flags & WASHALFOP)
#define chan_stopcheck(x)    (x->flags & STOPCHECK)
#define chan_whosynced(x)    (x->flags & WHO_SYNCED)
#define chan_ircaway(x)      (x->flags & IRCAWAY)
#define chan_ircbot(x)       (x->flags & IRCBOT)

/* Why duplicate this struct for exempts and invites only under another
 * name? <cybah>
 */
typedef struct maskstruct {
  char *mask;
  char *who;
  time_t timer;
  struct maskstruct *next;
} masklist;

/* Used for temporary bans, exempts and invites */
typedef struct maskrec {
  struct maskrec *next;
  char *mask,
       *desc,
       *user;
  time_t expire,
         added,
         lastactive;
  int flags;
} maskrec;
extern maskrec *global_bans, *global_exempts, *global_invites;

constexpr int MASKREC_STICKY = 1;
constexpr int MASKREC_PERM   = 2;

/* For every channel i join */
struct chan_t {
  memberlist *member;
  masklist *ban;
  masklist *exempt;
  masklist *invite;
  char *topic;
  char *key;
  unsigned int mode;
  int maxmembers;
  int members;
};

constexpr unsigned int CHANINV    = 0x0001;  /* i                        */
constexpr unsigned int CHANPRIV   = 0x0002;  /* p                        */
constexpr unsigned int CHANSEC    = 0x0004;  /* s                        */
constexpr unsigned int CHANMODER  = 0x0008;  /* m                        */
constexpr unsigned int CHANTOPIC  = 0x0010;  /* t                        */
constexpr unsigned int CHANNOMSG  = 0x0020;  /* n                        */
constexpr unsigned int CHANLIMIT  = 0x0040;  /* l                        */
constexpr unsigned int CHANKEY    = 0x0080;  /* k                        */
constexpr unsigned int CHANANON   = 0x0100;  /* a - ircd 2.9             */
constexpr unsigned int CHANQUIET  = 0x0200;  /* q - ircd 2.9             */
constexpr unsigned int CHANNOCLR  = 0x0400;  /* c - Bahamut              */
constexpr unsigned int CHANREGON  = 0x0800;  /* R - Bahamut              */
constexpr unsigned int CHANMODREG = 0x1000;  /* M - Bahamut              */
constexpr unsigned int CHANNOCTCP = 0x2000;  /* C - QuakeNet's ircu 2.10 */
constexpr unsigned int CHANLONLY  = 0x4000;  /* r - ircu 2.10.11         */
constexpr unsigned int CHANDELJN  = 0x8000;  /* D - QuakeNet's asuka     */
constexpr unsigned int CHANSTRIP  = 0x10000; /* u - QuakeNet's asuka     */
constexpr unsigned int CHANNONOTC = 0x20000; /* N - QuakeNet's asuka     */
constexpr unsigned int CHANINVIS  = 0x40000; /* d - QuakeNet's asuka     */
constexpr unsigned int CHANNOAMSG = 0x80000; /* T - QuakeNet's snircd    */

/* op_cidr_tbl_t: pointer-only forward decl for TUs that don't include op_lib.h.
 * The full typedef lives in op_cidr_tbl.h (included by op_lib.h); the guard
 * LIBOP_CIDR_TBL_H prevents a duplicate-typedef error when both are present. */
#ifndef LIBOP_CIDR_TBL_H
typedef struct op_cidr_tbl op_cidr_tbl_t;
#endif

struct chanset_t {
  struct chanset_t *next;
  struct chan_t channel;
  char dname[CHANNELLEN + 1]; /* display name (!foo) - THIS IS ALWAYS SET */
  char name[CHANNELLEN + 1];  /* actual name (!BARfoo) - THIS IS SET WHEN THE BOT
                               * ACTUALLY JOINS THE CHANNEL */
  char need_op[121];
  char need_key[121];
  char need_limit[121];
  char need_unban[121];
  char need_invite[121];
  int flood_pub_thr;
  int flood_pub_time;
  int flood_join_thr;
  int flood_join_time;
  int flood_deop_thr;
  int flood_deop_time;
  int flood_kick_thr;
  int flood_kick_time;
  int flood_ctcp_thr;
  int flood_ctcp_time;
  int flood_nick_thr;
  int flood_nick_time;
  int aop_min;
  int aop_max;
  long status;
  int ircnet_status;
  int idle_kick;
  int stopnethack_mode;
  int revenge_mode;
  int ban_type;
  int ban_time;
  int invite_time;
  int exempt_time;
  maskrec *bans,         /* temporary channel bans            */
          *exempts,      /* temporary channel exempts         */
          *invites;      /* temporary channel invites         */
  op_cidr_tbl_t *ban_ip_trie;    /* CIDR ban fast path (libop op_cidr_tbl)    */
  op_cidr_tbl_t *exempt_ip_trie; /* CIDR exempt fast path                     */
  op_cidr_tbl_t *invite_ip_trie; /* CIDR invite fast path                     */
  int mode_pls_prot;     /* modes to enforce                  */
  int mode_mns_prot;     /* modes to reject                   */
  int limit_prot;        /* desired limit                     */
  char key_prot[121];    /* desired password                  */
  char pls[21];          /* positive mode changes             */
  char mns[21];          /* negative mode changes             */
  char *key;             /* new key to set                    */
  char *rmkey;           /* old key to remove                 */
  int limit;             /* new limit to set                  */
  int bytes;             /* total bytes so far                */
  int compat;            /* prevents mixing of old/new modes  */
  struct {
    char *op;
    int type;
  } cmode[MODES_PER_LINE_MAX];
  char floodwho[FLOOD_CHAN_MAX][256]; /* can be nick or host */
  time_t floodtime[FLOOD_CHAN_MAX];
  int floodnum[FLOOD_CHAN_MAX];
  char deopd[NICKLEN];   /* last user deopped                 */
  /* IRCX-specific per-channel settings */
  char ircx_ownerkey[128]; /* OWNERKEY for JOIN to get +q       */
  int  ircx_create;        /* use CREATE if channel is missing  */
  char ircx_create_modes[32]; /* modes applied after CREATE     */
};

constexpr long CHAN_ENFORCEBANS    = 0x0001;     /* +enforcebans    */
constexpr long CHAN_DYNAMICBANS    = 0x0002;     /* +dynamicbans    */
constexpr long CHAN_NOUSERBANS     = 0x0004;     /* -userbans       */
constexpr long CHAN_OPONJOIN       = 0x0008;     /* +autoop         */
constexpr long CHAN_BITCH          = 0x0010;     /* +bitch          */
constexpr long CHAN_GREET          = 0x0020;     /* +greet          */
constexpr long CHAN_PROTECTOPS     = 0x0040;     /* +protectops     */
constexpr long CHAN_LOGSTATUS      = 0x0080;     /* +statuslog      */
constexpr long CHAN_REVENGE        = 0x0100;     /* +revenge        */
constexpr long CHAN_SECRET         = 0x0200;     /* +secret         */
constexpr long CHAN_AUTOVOICE      = 0x0400;     /* +autovoice      */
constexpr long CHAN_CYCLE          = 0x0800;     /* +cycle          */
constexpr long CHAN_DONTKICKOPS    = 0x1000;     /* +dontkickops    */
constexpr long CHAN_INACTIVE       = 0x2000;     /* +inactive       */
constexpr long CHAN_PROTECTFRIENDS = 0x4000;     /* +protectfriends */
constexpr long CHAN_SHARED         = 0x8000;     /* +shared         */
constexpr long CHAN_SEEN           = 0x10000;    /* +seen           */
constexpr long CHAN_REVENGEBOT     = 0x20000;    /* +revengebot     */
constexpr long CHAN_NODESYNCH      = 0x40000;    /* +nodesynch      */
constexpr long CHAN_AUTOHALFOP     = 0x80000;    /* +autohalfop     */
constexpr long CHAN_PROTECTHALFOPS = 0x100000;   /* +protecthalfops */
constexpr long CHAN_ACTIVE         = 0x200000;   /* -inactive       */

constexpr long CHAN_WHINED         = 0x1000000;  /* whined about opless channel      */
constexpr long CHAN_PEND           = 0x2000000;  /* waiting for end of WHO list      */
constexpr long CHAN_FLAGGED        = 0x4000000;  /* flagged for delete during rehash */
constexpr long CHAN_STATIC         = 0x8000000;  /* non-dynamic channel              */
constexpr long CHAN_ASKEDBANS      = 0x10000000;
constexpr long CHAN_ASKEDMODES     = 0x20000000; /* find out key-info on IRCu        */
constexpr long CHAN_JUPED          = 0x40000000; /* channel is juped                 */
constexpr long CHAN_STOP_CYCLE     = 0x80000000; /* NO_CHANOPS_WHEN_SPLIT servers    */

constexpr int CHAN_ASKED_EXEMPTS  = 0x0001;
constexpr int CHAN_ASKED_INVITED  = 0x0002;

constexpr int CHAN_DYNAMICEXEMPTS = 0x0004;
constexpr int CHAN_NOUSEREXEMPTS  = 0x0008;
constexpr int CHAN_DYNAMICINVITES = 0x0010;
constexpr int CHAN_NOUSERINVITES  = 0x0020;

/* prototypes */
[[nodiscard]] memberlist *ismember(struct chanset_t *, char *);
[[nodiscard]] struct chanset_t *findchan(const char *name);
[[nodiscard]] struct chanset_t *findchan_by_dname(const char *name);

#define channel_hidden(chan) (chan->channel.mode & (CHANPRIV | CHANSEC)) /* +s or +p ? */
#define channel_optopic(chan) (chan->channel.mode & CHANTOPIC) /* +t? */
#define channel_djoins(chan) (chan->status & (CHANDELJN | CHANINVIS)) /* +Dd? */

#define channel_active(chan)  (chan->status & CHAN_ACTIVE)
#define channel_pending(chan)  (chan->status & CHAN_PEND)
#define channel_bitch(chan) (chan->status & CHAN_BITCH)
#define channel_nodesynch(chan) (chan->status & CHAN_NODESYNCH)
#define channel_autoop(chan) (chan->status & CHAN_OPONJOIN)
#define channel_autovoice(chan) (chan->status & CHAN_AUTOVOICE)
#define channel_autohalfop(chan) (chan->status & CHAN_AUTOHALFOP)
#define channel_greet(chan) (chan->status & CHAN_GREET)
#define channel_logstatus(chan) (chan->status & CHAN_LOGSTATUS)
#define channel_enforcebans(chan) (chan->status & CHAN_ENFORCEBANS)
#define channel_revenge(chan) (chan->status & CHAN_REVENGE)
#define channel_dynamicbans(chan) (chan->status & CHAN_DYNAMICBANS)
#define channel_nouserbans(chan) (chan->status & CHAN_NOUSERBANS)
#define channel_protectops(chan) (chan->status & CHAN_PROTECTOPS)
#define channel_protecthalfops(chan) (chan->status & CHAN_PROTECTHALFOPS)
#define channel_protectfriends(chan) (chan->status & CHAN_PROTECTFRIENDS)
#define channel_dontkickops(chan) (chan->status & CHAN_DONTKICKOPS)
#define channel_secret(chan) (chan->status & CHAN_SECRET)
#define channel_shared(chan) (chan->status & CHAN_SHARED)
#define channel_static(chan) (chan->status & CHAN_STATIC)
#define channel_cycle(chan) (chan->status & CHAN_CYCLE)
#define channel_seen(chan) (chan->status & CHAN_SEEN)
#define channel_inactive(chan) (chan->status & CHAN_INACTIVE)
#define channel_revengebot(chan) (chan->status & CHAN_REVENGEBOT)
#define channel_dynamicexempts(chan) (chan->ircnet_status & CHAN_DYNAMICEXEMPTS)
#define channel_nouserexempts(chan) (chan->ircnet_status & CHAN_NOUSEREXEMPTS)
#define channel_dynamicinvites(chan) (chan->ircnet_status & CHAN_DYNAMICINVITES)
#define channel_nouserinvites(chan) (chan->ircnet_status & CHAN_NOUSERINVITES)
#define channel_juped(chan) (chan->status & CHAN_JUPED)
#define channel_stop_cycle(chan) (chan->status & CHAN_STOP_CYCLE)
#define channel_whined(chan) (chan->status & CHAN_WHINED)

struct msgq_head {
  struct msgq *head;
  struct msgq *last;
  int tot;
  int warned;
};

/* Used to queue a lot of things */
struct msgq {
  struct msgq *next;
  int len;
  char *msg;
};

#endif /* _EGG_CHAN_H */
