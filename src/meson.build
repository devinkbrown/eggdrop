# =========================================================================
# src/meson.build — eggdrop core binary + all modules
# =========================================================================

fs = import('fs')

# -------------------------------------------------------------------------
# Compatibility library (replaces missing libc functions)
# -------------------------------------------------------------------------
compat_sources = files(
  'compat/base64.c',
  'compat/explicit_bzero.c',
  'compat/in6.c',
  'compat/inet_aton.c',
  'compat/snprintf.c',
  'compat/strlcpy.c',
)

# arc4random — only compile our copy if the system lacks it
if not cdata.has('HAVE_ARC4RANDOM')
  compat_sources += files('compat/arc4random.c')
endif

# balloc slab allocator (always included)
if fs.exists(meson.current_source_dir() / 'compat/balloc.c')
  compat_sources += files('compat/balloc.c')
endif

# mbuf message ring buffer (always included when present)
if fs.exists(meson.current_source_dir() / 'compat/mbuf.c')
  compat_sources += files('compat/mbuf.c')
endif

compat_lib = static_library('eggcompat',
  sources: compat_sources,
  include_directories: [top_inc, src_inc],
  c_args: ['-DHAVE_CONFIG_H'],
  dependencies: [tcl_dep, tls_dep],
)
compat_dep = declare_dependency(link_with: compat_lib)

# -------------------------------------------------------------------------
# MD5 library
# -------------------------------------------------------------------------
md5_lib = static_library('eggmd5',
  sources: ['md5/md5c.c'],
  include_directories: [top_inc, src_inc],
  c_args: ['-DHAVE_CONFIG_H'],
)
md5_dep = declare_dependency(link_with: md5_lib)

# -------------------------------------------------------------------------
# Core eggdrop sources
# -------------------------------------------------------------------------
core_sources = files(
  'bg.c',
  'botcmd.c',
  'configtoml.c',
  'botmsg.c',
  'botnet.c',
  'chanprog.c',
  'cmds.c',
  'dcc.c',
  'dccutil.c',
  'dns.c',
  'flags.c',
  'language.c',
  'main.c',
  'match.c',
  'mem.c',
  'misc.c',
  'misc_file.c',
  'modules.c',
  'net.c',
  'rfc1459.c',
  'tcl.c',
  'tcldcc.c',
  'tclhash.c',
  'tclmisc.c',
  'tcluser.c',
  'tls.c',
  'userent.c',
  'userrec.c',
  'users.c',
)

# Optional new data-structure sources (from ophion import)
foreach s : ['patricia.c', 'dictionary.c']
  if fs.exists(meson.current_source_dir() / s)
    core_sources += files(s)
  endif
endforeach

# -------------------------------------------------------------------------
# Core compile flags
# -------------------------------------------------------------------------
core_cargs = [
  '-DHAVE_CONFIG_H',
  '-DEGG_VERSION="@0@"'.format(meson.project_version()),
  '-DHANDLEN=@0@'.format(opt_handlen),
]

# -DDEBUG_MEM is eggdrop-specific (memory tracking); the generic -DDEBUG/-g
# flags are applied globally via add_project_arguments() in the top meson.build.
if opt_debug
  core_cargs += ['-DDEBUG_MEM']
endif

# -------------------------------------------------------------------------
# All link dependencies for the main binary
# -------------------------------------------------------------------------
eggdrop_deps = [
  tcl_dep,
  compat_dep,
  md5_dep,
]

if have_tls
  eggdrop_deps += tls_dep
endif
if have_tdns
  eggdrop_deps += thread_dep
endif
if have_uring
  eggdrop_deps += uring_dep
endif
if dl_dep.found()
  eggdrop_deps += dl_dep
endif
if resolv_dep.found()
  eggdrop_deps += resolv_dep
endif
if nsl_dep.found()
  eggdrop_deps += nsl_dep
endif
if m_dep.found()
  eggdrop_deps += m_dep
endif
if ws2_dep.found()
  eggdrop_deps += ws2_dep
endif
if mswsock_dep.found()
  eggdrop_deps += mswsock_dep
endif

# -------------------------------------------------------------------------
# Module definitions
# Each entry: name, sources, extra_deps ([] if none)
# Each module uses a "unity build": the top-level .c file #includes all
# others in the module directory, so only the top-level file is listed here.
module_defs = [
  {'name': 'assoc',    'sources': ['mod/assoc.mod/assoc.c'],       'deps': []},
  {'name': 'blowfish', 'sources': ['mod/blowfish.mod/blowfish.c'], 'deps': []},
  {'name': 'channels', 'sources': ['mod/channels.mod/channels.c'], 'deps': []},
  {'name': 'console',  'sources': ['mod/console.mod/console.c'],   'deps': []},
  {'name': 'ctcp',     'sources': ['mod/ctcp.mod/ctcp.c'],         'deps': []},
  {
    'name': 'dns',
    # When use-res-dns is true, compile res.c directly as the module
    # source (it includes eggdrop.h standalone and exposes the same
    # compat API as coredns.c).  The default uses dns.c which #includes
    # coredns.c in the traditional unity-build fashion.
    'sources': get_option('use-res-dns')
               ? ['mod/dns.mod/res.c']
               : ['mod/dns.mod/dns.c'],
    'deps': [],   # resolv_dep added per-module below if found
  },
  {'name': 'filesys',  'sources': ['mod/filesys.mod/filesys.c'],   'deps': []},
  {'name': 'ident',    'sources': ['mod/ident.mod/ident.c'],       'deps': []},
  {'name': 'irc',      'sources': ['mod/irc.mod/irc.c'],           'deps': []},
  {'name': 'notes',    'sources': ['mod/notes.mod/notes.c'],       'deps': []},
  {'name': 'pbkdf2',   'sources': ['mod/pbkdf2.mod/pbkdf2.c'],     'deps': []},
  {'name': 'seen',     'sources': ['mod/seen.mod/seen.c'],         'deps': []},
  {
    'name': 'server',
    'sources': ['mod/server.mod/server.c'],   # includes isupport.c, servmsg.c, etc.
    'deps': [],   # tls_dep added per-module below if found
  },
  {'name': 'share',    'sources': ['mod/share.mod/share.c'],       'deps': []},
  {'name': 'transfer', 'sources': ['mod/transfer.mod/transfer.c'], 'deps': []},
  {'name': 'twitch',   'sources': ['mod/twitch.mod/twitch.c'],     'deps': []},
  {'name': 'uptime',   'sources': ['mod/uptime.mod/uptime.c'],     'deps': []},
  {
    'name': 'webui',
    'sources': ['mod/webui.mod/webui.c'],
    'deps': [],   # tls_dep added per-module below if found
  },
  {'name': 'woobie',   'sources': ['mod/woobie.mod/woobie.c'],     'deps': []},
]

# Compress module — only if zlib found AND user wants it
if have_zlib and get_option('module-compress')
  module_defs += [{
    'name': 'compress',
    'sources': ['mod/compress.mod/compress.c'],
    'deps': [zlib_dep],
  }]
endif

# Python module — only if Python 3.8+ found AND user wants it
if have_python and get_option('module-python')
  module_defs += [{
    'name': 'python',
    'sources': ['mod/python.mod/python.c'],
    'deps': [python3.dependency()],
  }]
endif

# -------------------------------------------------------------------------
# Filter module list by per-module options
# -------------------------------------------------------------------------
enabled_module_defs = []
foreach m : module_defs
  if get_option('module-' + m['name'])
    enabled_module_defs += [m]
  endif
endforeach

# -------------------------------------------------------------------------
# Module compile flags (shared by all modules)
# -------------------------------------------------------------------------
# -fvisibility=hidden: hide all symbols by default in modules; only the
# entry point decorated with EXPORT_SCOPE is visible to dlopen().
_fvis = (not is_native_windows and cc.has_argument('-fvisibility=hidden')) \
        ? ['-fvisibility=hidden'] : []

module_cargs = core_cargs + ['-DMAKING_MODS'] + _fvis

module_inc = [top_inc, src_inc, include_directories('mod')]

# -------------------------------------------------------------------------
# libeggres — standalone static library built from res.c
#
# res.c is a self-contained alternative DNS resolver that includes
# eggdrop.h directly.  We compile it as a static library so it is
# available for future linking (e.g. swapped-in via use-res-dns) without
# being part of the normal dns module unity build.  The library is only
# built when res.c is present in the source tree.
# -------------------------------------------------------------------------
if fs.exists(meson.current_source_dir() / 'mod/dns.mod/res.c')
  # res.c is compiled WITHOUT -DMAKING_MODS so that main.h includes
  # proto.h, giving direct declarations for n_malloc/n_free, tputs,
  # getsock, killsock, findsock, ssl_handshake, threaddata, etc.
  # The module.h global[] dispatch macros require MODULE_NAME and an
  # initialised global[] vector which are only present inside a running
  # eggdrop module — they are not available in a standalone library.
  eggres_lib = static_library('eggres',
    sources: files('mod/dns.mod/res.c'),
    include_directories: [top_inc, src_inc],
    c_args: core_cargs,
    dependencies: [tcl_dep, tls_dep],
  )
  eggres_dep = declare_dependency(link_with: eggres_lib)
endif

# -------------------------------------------------------------------------
# Static build: compile modules as objects, link into binary
# -------------------------------------------------------------------------
if opt_static
  static_mod_sources = []
  foreach m : enabled_module_defs
    static_mod_sources += files(m['sources'])
  endforeach

  eggdrop_exe = executable(opt_exec,
    sources: core_sources + static_mod_sources,
    include_directories: [top_inc, src_inc, mod_inc],
    c_args: core_cargs + ['-DSTATIC'],
    dependencies: eggdrop_deps,
    install: true,
  )

# -------------------------------------------------------------------------
# Dynamic build: build each module as a shared_module
# -------------------------------------------------------------------------
else
  # Build the eggdrop binary (no module objects linked in)
  eggdrop_exe = executable(opt_exec,
    sources: core_sources,
    include_directories: [top_inc, src_inc, mod_inc],
    c_args: core_cargs,
    dependencies: eggdrop_deps,
    export_dynamic: true,   # allow modules to call back into binary
    install: true,
  )

  # Install path for modules
  modules_dir = get_option('libdir') / 'eggdrop' / meson.project_version()

  # Build each enabled module
  foreach m : enabled_module_defs
    mod_deps = eggdrop_deps + m['deps']
    # Per-module conditional dependencies
    if m['name'] == 'dns' and resolv_dep.found()
      mod_deps += resolv_dep
    endif
    if m['name'] in ['server', 'webui'] and have_tls
      mod_deps += tls_dep
    endif

    shared_module(m['name'],
      sources: files(m['sources']),
      include_directories: module_inc,
      c_args: module_cargs,
      dependencies: mod_deps,
      name_prefix: '',
      name_suffix: mod_ext,
      install: true,
      install_dir: modules_dir,
    )
  endforeach
endif

# -------------------------------------------------------------------------
# Install: scripts, help, language, config, text
# (paths relative to project root, not src/)
# -------------------------------------------------------------------------
_root = meson.project_source_root()
_ddir = get_option('datadir') / 'eggdrop'
install_subdir(_root / 'scripts',  install_dir: _ddir, strip_directory: true)
install_subdir(_root / 'help',     install_dir: _ddir, strip_directory: true)
install_subdir(_root / 'language', install_dir: _ddir, strip_directory: true)
# TOML configuration files — primary format, no chmod required.
install_data(_root / 'eggdrop.toml',       install_dir: _ddir)
install_data(_root / 'eggdrop-basic.toml', install_dir: _ddir)

# -------------------------------------------------------------------------
# Distribution note
# -------------------------------------------------------------------------
# `meson dist` is built-in — running it from the build directory produces
# a release tarball automatically (no custom_target needed).

# -------------------------------------------------------------------------
# Post-install script
# Creates pid/ and logs/ directories under the eggdrop data directory.
# -------------------------------------------------------------------------
meson.add_install_script('../misc/post_install.py',
  get_option('prefix'),
  get_option('datadir'))
