/*
 * egg_store_flat.c — legacy flat-file storage backend.
 *
 * This is a thin wrapper around the existing readuserfile() and
 * write_userfile() functions, providing them through the egg_store_backend_t
 * interface.  It allows the legacy text format to be used as a fallback
 * or for share module transfers.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "main.h"
#include "egg_store.h"
#include "users.h"

extern struct userrec *userlist;
extern char userfile[];
extern int readuserfile(char *, struct userrec **);
extern void write_userfile(int);

static int flat_open(const char *path)
{
  return 0;  /* No-op: flat files don't need an open step. */
}

static void flat_close(void)
{
  /* No-op. */
}

static int flat_load_users(const char *path, struct userrec **list)
{
  return readuserfile((char *) path, list);
}

static void flat_save_users(int idx)
{
  write_userfile(idx);
}

static int flat_load_channels(void)
{
  /* Channels are loaded via Tcl `source` of the .chan file.
   * This is handled by channels.mod's HOOK_REHASH handler. */
  return 1;
}

static void flat_save_channels(void)
{
  /* Channels are saved by the channels.mod HOOK_USERFILE handler.
   * Nothing extra needed here. */
}

static int flat_export(const char *path)
{
  /* The flat backend IS the flat format — just write normally. */
  write_userfile(-1);
  return 1;
}

static int flat_import(const char *path)
{
  return readuserfile((char *) path, &userlist);
}

egg_store_backend_t egg_store_flat = {
  .name           = "flat",
  .open           = flat_open,
  .close          = flat_close,
  .load_users     = flat_load_users,
  .save_users     = flat_save_users,
  .load_channels  = flat_load_channels,
  .save_channels  = flat_save_channels,
  .export_flat    = flat_export,
  .import_flat    = flat_import,
};
