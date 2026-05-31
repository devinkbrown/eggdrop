# =========================================================================
# libop/src/meson.build — portable data-structure + commio static library
#
# Embedded in Eggdrop as a static library.  Keep the source list aligned with
# Ophion libop, plus Eggdrop-local helpers that have not moved upstream.
# =========================================================================

libop_sources = files(
  # Memory / allocation
  'op_memory.c',
  'op_memory_ext.c',
  'balloc.c',
  'arena.c',

  # Core containers
  'htab.c',
  'rawbuf.c',
  'strbuf.c',
  'bloom.c',

  # Data structures
  'rbt.c',
  'vec.c',
  'deque.c',
  'skiplist.c',
  'trie.c',
  'itree.c',
  'cidr_tbl.c',
  'graph.c',
  'pqueue.c',
  'str_intern.c',
  'hll.c',
  'wm.c',
  'lru.c',

  # Utilities
  'tools.c',
  'utf8.c',
  'simd_scan.c',
  'regex.c',
  'hostmask.c',
  'msgbuf.c',
  'subst.c',

  # Threading
  'thread_pool.c',
  'op_atomic.c',

  # Extended utilities
  'crypt.c',
  'toml.c',
  'version.c',
  'coro.c',
  'shm_ring.c',
  'async.c',
  'async_log.c',
  'helper.c',
  'seccomp.c',
  'lock_debug.c',
  'crdt.c',

  # Portability fallbacks
  'arc4random.c',

  # Core library init, clock, callbacks, base64, strtok_r, etc.
  'op_lib.c',

  # commio I/O layer
  'sha1.c',
  'websocket.c',
  'commio.c',
  'linebuf.c',
  'sendbuf.c',
  'event.c',
  'epoll.c',
  'io_uring.c',
  'kqueue.c',
  'poll.c',
  'select.c',
  'iocp.c',
  'ports.c',
  'devpoll.c',
  'sigio.c',
  'unix.c',
)

if have_ssl
  libop_sources += files('opssl_backend.c')
else
  libop_sources += files('ssl_stubs.c')
endif

fs = import('fs')
thread_dep = dependency('threads', required: true)
libm_dep = meson.get_compiler('c').find_library('m', required: false)

libop_c_args = ['-DHAVE_CONFIG_H', '-std=gnu23', '-Wno-stringop-overread']
if have_ssl
  libop_c_args += ['-DHAVE_OPSSL=1']
endif

_top_inc = include_directories('../..')
_src_inc = include_directories('../../src')

_libop_core_obj = static_library('_op_core',
  sources: libop_sources,
  include_directories: [libop_inc],
  dependencies: have_ssl
    ? [thread_dep, libm_dep, opssl_dep]
    : [thread_dep, libm_dep],
  c_args: libop_c_args,
  pic: true,
  override_options: ['c_std=gnu23'],
)

compat_sources_merged = files(
  '../../src/compat/base64.c',
  '../../src/compat/explicit_bzero.c',
  '../../src/compat/in6.c',
  '../../src/compat/inet_aton.c',
  '../../src/md5/md5c.c',
)
if fs.exists(meson.current_source_dir() / '../../src/compat/mbuf.c')
  compat_sources_merged += files('../../src/compat/mbuf.c')
endif

_libop_compat_obj = static_library('_op_compat',
  sources: compat_sources_merged,
  include_directories: [libop_inc, _top_inc, _src_inc],
  c_args: ['-DHAVE_CONFIG_H', '-DCOMPILING_MEM'],
  pic: true,
)

_libop_lmdb_obj = static_library('_op_lmdb',
  sources: files('lmdb/mdb.c', 'lmdb/midl.c'),
  include_directories: [include_directories('lmdb')],
  c_args: ['-DMDB_USE_POSIX_MUTEX=1', '-Wno-unused-parameter', '-Wno-format-extra-args'],
  pic: true,
)

libop_ds = static_library('op',
  objects: [
    _libop_core_obj.extract_all_objects(recursive: true),
    _libop_compat_obj.extract_all_objects(recursive: true),
    _libop_lmdb_obj.extract_all_objects(recursive: true),
  ],
  dependencies: have_ssl
    ? [thread_dep, libm_dep, opssl_dep]
    : [thread_dep, libm_dep],
  pic: true,
)

lmdb_inc = include_directories('lmdb')

libop_dep = declare_dependency(
  link_whole: libop_ds,
  include_directories: [libop_inc, lmdb_inc],
)
