/*
 * modvals.h
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

#ifndef _EGG_MOD_MODVALS_H
#define _EGG_MOD_MODVALS_H

/* HOOK_GET_FLAGREC   = 0 */
/* HOOK_BUILD_FLAGREC = 1 */
/* HOOK_SET_FLAGREC   = 2 */
constexpr int HOOK_READ_USERFILE             =  3;
constexpr int HOOK_REHASH                    =  4;
constexpr int HOOK_MINUTELY                  =  5;
constexpr int HOOK_DAILY                     =  6;
constexpr int HOOK_HOURLY                    =  7;
constexpr int HOOK_USERFILE                  =  8;
constexpr int HOOK_SECONDLY                  =  9;
constexpr int HOOK_PRE_REHASH               = 10;
constexpr int HOOK_IDLE                     = 11;
constexpr int HOOK_5MINUTELY                = 12;
constexpr int HOOK_LOADED                   = 13;
constexpr int HOOK_BACKUP                   = 14;
constexpr int HOOK_DIE                      = 15;
constexpr int HOOK_PRE_SELECT               = 16;
constexpr int HOOK_POST_SELECT              = 17;

constexpr int REAL_HOOKS                    = 18;

constexpr int HOOK_SHAREOUT                = 105;
constexpr int HOOK_SHAREIN                 = 106;
constexpr int HOOK_ENCRYPT_PASS            = 107;
constexpr int HOOK_QSERV                   = 108;
constexpr int HOOK_ADD_MODE                = 109;
constexpr int HOOK_MATCH_NOTEREJ           = 110;
constexpr int HOOK_RFC_CASECMP             = 111;
constexpr int HOOK_DNS_HOSTBYIP            = 112;
constexpr int HOOK_DNS_IPBYHOST            = 113;
constexpr int HOOK_ENCRYPT_STRING          = 114;
constexpr int HOOK_DECRYPT_STRING          = 115;
constexpr int HOOK_ENCRYPT_PASS2           = 116;
constexpr int HOOK_VERIFY_PASS2            = 117;
constexpr int HOOK_DCC_TELNET_HOSTRESOLVED = 118;
constexpr int HOOK_WEBUI_FRAME             = 119;
constexpr int HOOK_WEBUI_UNFRAME           = 120;
constexpr int HOOK_LOG                     = 121;

/* These are FIXED once they are in a release they STAY */
constexpr int MODCALL_START   = 0;
constexpr int MODCALL_CLOSE   = 1;
constexpr int MODCALL_EXPMEM  = 2;
constexpr int MODCALL_REPORT  = 3;
/* Filesys */
constexpr int FILESYS_REMOTE_REQ = 4;
constexpr int FILESYS_ADDFILE    = 5;
constexpr int FILESYS_INCRGOTS   = 6;
constexpr int FILESYS_ISVALID    = 7;
/* Share */
constexpr int SHARE_FINISH     = 4;
constexpr int SHARE_DUMP_RESYNC = 5;
/* Channels */
constexpr int CHANNEL_CLEAR = 15;
/* Server */
constexpr int SERVER_BOTNAME    =  4;
constexpr int SERVER_BOTUSERHOST =  5;
constexpr int SERVER_NICKLEN    = 37;
/* IRC */
constexpr int IRC_RECHECK_CHANNEL       = 15;
constexpr int IRC_RECHECK_CHANNEL_MODES = 17;
constexpr int IRC_DO_CHANNEL_PART       = 19;
constexpr int IRC_CHECK_THIS_BAN        = 20;
constexpr int IRC_CHECK_THIS_USER       = 21;
constexpr int IRC_RESET_CHAN_INFO       = 25;
constexpr int IRC_FLUSH_MODE           = 29;
/* Notes */
constexpr int NOTES_CMD_NOTE  = 4;
/* Console */
constexpr int CONSOLE_DOSTORE = 4;

#ifdef MOD_USE_SHL
#  include <dl.h>
#endif

#ifdef MOD_USE_DYLD
#  include <mach-o/dyld.h>
#endif

#ifdef MOD_USE_LOADER
#  include <loader.h>
#endif

typedef struct _module_entry {
  char *name;                   /* Name of the module (without .so)     */
  int major;                    /* Major version number MUST match      */
  int minor;                    /* Minor version number MUST be >=      */
  int patch;                    /* Patch version for semver checking    */
#ifndef STATIC
#  ifdef MOD_USE_SHL
  shl_t hand;
#  endif
#  ifdef MOD_USE_DYLD
  NSModule hand;
#  endif
#  ifdef MOD_USE_LOADER
  ldr_module_t hand;
#  endif
#  ifdef MOD_USE_DL
  void *hand;
#  endif
#endif /* STATIC */
  Function *funcs;
} module_entry;

/* -----------------------------------------------------------------------
 * Versioned API struct — wraps the legacy global_table with metadata.
 *
 * Old modules use Function *global unchanged.  New modules can verify
 * ABI compatibility via version/count before calling through the table.
 * The struct is append-only: new fields go after 'funcs', count grows
 * monotonically, and version bumps only on incompatible layout changes.
 * ----------------------------------------------------------------------- */
#define EGG_API_VERSION  1

typedef struct eggdrop_api {
  uint32_t  version;   /* EGG_API_VERSION                              */
  uint32_t  count;     /* number of entries in the function table       */
  Function *funcs;     /* points to global_table[]                      */
} eggdrop_api_t;

/* Slot in global_table that holds a pointer to the eggdrop_api_t.
 * New modules: egg_api->version / egg_api->count for ABI checks. */
#define EGG_API_SLOT 335

#endif /* _EGG_MOD_MODVALS_H */
