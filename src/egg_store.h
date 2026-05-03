/*
 * egg_store.h — pluggable storage backend for user/channel/bot records.
 *
 * Provides a vtable-based abstraction over the persistence layer.
 * Two backends:
 *   "flat"  — the legacy text-based userfile format (default fallback)
 *   "lmdb"  — LMDB-backed structured key-value store (default)
 *
 * The in-memory representation (struct userrec linked list, op_htab indices,
 * chanset_t linked list) is completely unchanged.  This layer only controls
 * how that data is serialized to and from disk.
 *
 * Copyright (C) 2026 Eggheads Development Team
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _EGG_STORE_H
#define _EGG_STORE_H

struct userrec;

/* Storage backend vtable. */
typedef struct egg_store_backend {
  const char *name;

  /* Open/create the database at `path`.  Returns 0 on success. */
  int  (*open)(const char *path);

  /* Close the database, flush pending writes. */
  void (*close)(void);

  /* Load all user records from storage into the in-memory linked list.
   * Populates *list and rebuilds the handle hash table.
   * Returns 1 on success, 0 on failure. */
  int  (*load_users)(const char *path, struct userrec **list);

  /* Persist the current in-memory user list to storage.
   * `idx` is the DCC index requesting the save (for error output), or -1. */
  void (*save_users)(int idx);

  /* Load channel settings from storage. Returns 1 on success. */
  int  (*load_channels)(void);

  /* Save channel settings to storage. */
  void (*save_channels)(void);

  /* Export the current in-memory state to legacy flat-file format.
   * Used for share module transfers and manual backup.  Returns 1 on success. */
  int  (*export_flat)(const char *path);

  /* Import from a legacy flat-file into the in-memory state (and persist). */
  int  (*import_flat)(const char *path);
} egg_store_backend_t;

/* Currently active storage backend. */
extern egg_store_backend_t *egg_store;

/* Available backends. */
extern egg_store_backend_t egg_store_flat;
extern egg_store_backend_t egg_store_lmdb;

/* Initialize the storage subsystem.  Picks the backend based on the
 * `store_backend` config variable and opens the database. */
void egg_store_init(void);

/* Shut down the storage subsystem. */
void egg_store_shutdown(void);

/* Config variable: "lmdb" or "flat". */
extern char store_backend[16];

/* Config variable: path to the LMDB database directory. */
extern char store_path[121];

#endif /* _EGG_STORE_H */
