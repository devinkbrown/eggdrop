/*
 * shard.h -- Eggdrop libop I/O shard worker runtime
 */

#ifndef _EGG_SHARD_H
#define _EGG_SHARD_H

#define EGG_IO_SHARDS_MAX 32

int egg_shards_resolve_count(int configured);
int egg_shards_start(int count);
void egg_shards_shutdown(void);
int egg_shards_count(void);
int egg_shards_running(void);

#endif /* _EGG_SHARD_H */
