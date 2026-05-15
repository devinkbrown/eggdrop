/*
 * egg_store.c — storage backend dispatch layer.
 *
 * Selects and initializes the active storage backend based on the
 * `store_backend` configuration variable.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "main.h"
#include "egg_store.h"

/* Configuration variables (settable via set store-backend / eggdrop.toml). */
char store_backend[16] = "lmdb";
char store_path[121] = "";  /* Empty = auto-derive from botnetnick */

/* Active backend pointer. */
egg_store_backend_t *egg_store = nullptr;

extern char botnetnick[];

void egg_store_init(void)
{
  /* Pick backend. */
  if (!strcasecmp(store_backend, "flat")) {
    egg_store = &egg_store_flat;
  } else {
    /* Default to LMDB. */
    egg_store = &egg_store_lmdb;
  }

  /* Derive path if not explicitly set. */
  if (!store_path[0]) {
    if (egg_store == &egg_store_lmdb) {
      snprintf(store_path, sizeof store_path, "%s.mdb", botnetnick);
    }
    /* Flat backend uses the existing `userfile` global. */
  }

  /* Open the backend. */
  if (egg_store->open(store_path) != 0) {
    /* LMDB open failed — fall back to flat. */
    if (egg_store == &egg_store_lmdb) {
      putlog(LOG_MISC, "*", "Store: LMDB open failed, falling back to flat backend.");
      egg_store = &egg_store_flat;
      egg_store->open("");
    }
  }

  putlog(LOG_MISC, "*", "Store: using '%s' backend.", egg_store->name);
}

void egg_store_shutdown(void)
{
  if (egg_store) {
    egg_store->close();
    egg_store = nullptr;
  }
}
