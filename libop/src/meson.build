# =========================================================================
# libop/src/meson.build — portable data-structure + commio static library
#
# Includes the full ophion libop subset:
#   • Memory / allocators
#   • Data structures (Waves 67–69)
#   • Utilities
#   • commio I/O layer (replaces eggdrop's net.c)
#   • TLS via wolfSSL (wolfssl.c) or no-op stubs (wolfssl_nossl.c)
# =========================================================================

libop_sources = files(
  # Memory / allocation
  'op_memory.c',        # eggdrop OOM handler (abort instead of ircd restart)
  'balloc.c',           # mmap-backed slab allocator (op_bh_*)
  'arena.c',            # bump-pointer arena allocator (op_arena_*)

  # Core containers
  'htab.c',             # open-addressing hash table (op_htab_*)
  'rawbuf.c',           # circular byte buffer (op_rawbuf_*)
  'strbuf.c',           # growable string buffer (op_strbuf_*)
  'bloom.c',            # counting Bloom filter (op_bloom_*)

  # New data structures (Waves 67+)
  'rbt.c',              # LLRB red-black tree (op_rbt_*)
  'vec.c',              # dynamic array (op_vec_*)
  'deque.c',            # double-ended queue (op_deque_*)
  'skiplist.c',         # probabilistic ordered map (op_skiplist_*)
  'trie.c',             # ternary search trie (op_trie_*)
  'itree.c',            # augmented interval tree (op_itree_*)
  'cidr_tbl.c',         # IPv4/IPv6 CIDR prefix lookup (op_cidr_tbl_*)
  'graph.c',            # directed graph (op_graph_*)
  'pqueue.c',           # binary min-heap (op_pqueue_*)
  'str_intern.c',       # reference-counted string interning (op_str_intern_*)
  'hll.c',              # HyperLogLog estimator (op_hll_*)
  'wm.c',               # rate meters / moving averages (op_wm_*)
  'lru.c',              # LRU cache (op_lru_*)

  # Utilities
  'tools.c',            # misc helpers (op_strlcpy, op_basename, etc.)
  'utf8.c',             # UTF-8 validation and iteration (op_utf8_*)
  'simd_scan.c',        # SIMD-accelerated byte-scan (op_simd_find_delim etc.)

  # Threading
  'thread_pool.c',      # boss-worker thread pool (op_tpool_*)

  # Extended utilities (from ophion libop)
  'crypt.c',            # SHA-256/SHA-512 crypt (op_crypt)
  'toml.c',             # minimal TOML config parser (op_toml_*)
  'version.c',          # build identity / copyright metadata (op_build_info)
  'coro.c',             # stackful coroutines via ucontext_t (op_coro_*)
  'shm_ring.c',         # SPSC shared-memory ring buffer (op_shm_ring_*)
  'async.c',            # generic async task executor (op_async_*)
  'async_log.c',        # async log writer thread (op_async_log_*)
  'helper.c',           # helper process / in-process thread (op_helper_*)
  'seccomp.c',          # seccomp-bpf privilege restriction (self-guards __linux__)

  # Portability fallbacks
  'arc4random.c',       # arc4random / arc4random_buf when not in libc

  # Core library init, clock, callbacks, base64, strtok_r, etc.
  'op_lib.c',

  # commio I/O layer
  'sha1.c',             # SHA-1 (used by websocket.c handshake)
  'websocket.c',        # WebSocket framing layer (op_ws_read/write/shutdown)
  'commio.c',           # fd table, poll dispatch, sendq, accept/connect
  'linebuf.c',          # IRC line buffer (op_linebuf_*)
  'sendbuf.c',          # client send buffer (op_sendbuf_*)
  'event.c',            # timer events (op_event_*)
  'epoll.c',            # epoll backend
  'io_uring.c',         # io_uring backend
  'kqueue.c',           # kqueue backend (BSD/macOS)
  'poll.c',             # poll() fallback backend
  'select.c',           # select() fallback backend
  'iocp.c',             # Windows IOCP backend (64-bit; self-guards on _WIN32)
  'ports.c',            # Solaris event ports backend (self-guards on HAVE_PORT_CREATE)
  'devpoll.c',          # /dev/poll backend (self-guards on HAVE_DEVPOLL)
  'sigio.c',            # Linux RT-SIGIO backend (self-guards on F_SETSIG)
  'unix.c',             # process helpers (fork, socketpair, fd passing)
)

# TLS backend: real wolfssl or no-op stubs
if have_ssl
  libop_sources += files('wolfssl.c')
else
  libop_sources += files('wolfssl_nossl.c')
endif

fs = import('fs')
thread_dep = dependency('threads', required: true)
libm_dep   = meson.get_compiler('c').find_library('m', required: false)

libop_c_args = ['-DHAVE_CONFIG_H', '-std=gnu23']
if have_ssl
  libop_c_args += ['-DHAVE_WOLFSSL=1']
endif

_top_inc = include_directories('../..')
_src_inc = include_directories('../../src')

# -------------------------------------------------------------------------
# Compile libop core sources into an intermediate object library.
# -------------------------------------------------------------------------
_libop_core_obj = static_library('_op_core',
  sources:              libop_sources,
  include_directories:  [libop_inc],
  dependencies:         have_ssl
                          ? [thread_dep, libm_dep, wolfssl_dep]
                          : [thread_dep, libm_dep],
  c_args:               libop_c_args,
  pic:                  true,
  override_options:     ['c_std=gnu23'],
)

# -------------------------------------------------------------------------
# Eggdrop compat + MD5 — compiled into a second intermediate object library.
#
# COMPILING_MEM disables eggdrop.h's malloc→dont_use_old_malloc macro.
# HAVE_CONFIG_H ensures config.h is pulled in for feature flags.
# -------------------------------------------------------------------------
compat_sources_merged = files(
  '../../src/compat/base64.c',
  '../../src/compat/explicit_bzero.c',
  '../../src/compat/in6.c',
  '../../src/compat/inet_aton.c',
  '../../src/compat/snprintf.c',
  '../../src/compat/strlcpy.c',
  '../../src/md5/md5c.c',
)
if fs.exists(meson.current_source_dir() / '../../src/compat/mbuf.c')
  compat_sources_merged += files('../../src/compat/mbuf.c')
endif
if not cdata.has('HAVE_ARC4RANDOM')
  compat_sources_merged += files('../../src/compat/arc4random.c')
endif

_libop_compat_obj = static_library('_op_compat',
  sources:             compat_sources_merged,
  include_directories: [libop_inc, _top_inc, _src_inc],
  c_args:              ['-DHAVE_CONFIG_H', '-DCOMPILING_MEM'],
  dependencies:        have_ssl ? [wolfssl_dep] : [],
  pic:                 true,
)

# -------------------------------------------------------------------------
# Unified libop — single archive containing all object files.
# Consumers link only this one library; no separate compat/md5 libs needed.
# -------------------------------------------------------------------------
libop_ds = static_library('op',
  objects: [
    _libop_core_obj.extract_all_objects(recursive: true),
    _libop_compat_obj.extract_all_objects(recursive: true),
  ],
  dependencies: have_ssl
                  ? [thread_dep, libm_dep, wolfssl_dep]
                  : [thread_dep, libm_dep],
  pic: true,
)

libop_dep = declare_dependency(
  link_with:            libop_ds,
  include_directories:  [libop_inc],
)
