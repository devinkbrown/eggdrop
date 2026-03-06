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

compat_lib = static_library('eggcompat',
  sources: compat_sources,
  include_directories: [top_inc, src_inc],
  c_args: ['-DHAVE_CONFIG_H'],
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

if opt_debug
  core_cargs += ['-DDEBUG', '-DDEBUG_MEM', '-g']
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

# -------------------------------------------------------------------------
# Module definitions
# Each entry: name, sources, extra_deps ([] if none)
# -------------------------------------------------------------------------
module_defs = [
  {
    'name': 'assoc',
    'sources': ['mod/assoc.mod/assoc.c'],
    'deps': [],
  },
  {
    'name': 'blowfish',
    'sources': ['mod/blowfish.mod/blowfish.c'],
    'deps': [],
  },
  {
    'name': 'channels',
    'sources': [
      'mod/channels.mod/channels.c',
      'mod/channels.mod/cmdschan.c',
      'mod/channels.mod/tclchan.c',
      'mod/channels.mod/udefchan.c',
      'mod/channels.mod/userchan.c',
    ],
    'deps': [],
  },
  {
    'name': 'console',
    'sources': ['mod/console.mod/console.c'],
    'deps': [],
  },
  {
    'name': 'ctcp',
    'sources': ['mod/ctcp.mod/ctcp.c'],
    'deps': [],
  },
  {
    'name': 'dns',
    'sources': [
      'mod/dns.mod/dns.c',
      'mod/dns.mod/coredns.c',
    ],
    'deps': [],   # resolv_dep added per-module below if found
  },
  {
    'name': 'filesys',
    'sources': [
      'mod/filesys.mod/dbcompat.c',
      'mod/filesys.mod/filedb3.c',
      'mod/filesys.mod/filelist.c',
      'mod/filesys.mod/files.c',
      'mod/filesys.mod/filesys.c',
      'mod/filesys.mod/tclfiles.c',
    ],
    'deps': [],
  },
  {
    'name': 'ident',
    'sources': ['mod/ident.mod/ident.c'],
    'deps': [],
  },
  {
    'name': 'irc',
    'sources': [
      'mod/irc.mod/chan.c',
      'mod/irc.mod/cmdsirc.c',
      'mod/irc.mod/irc.c',
      'mod/irc.mod/mode.c',
      'mod/irc.mod/msgcmds.c',
      'mod/irc.mod/tclirc.c',
    ],
    'deps': [],
  },
  {
    'name': 'notes',
    'sources': [
      'mod/notes.mod/cmdsnote.c',
      'mod/notes.mod/notes.c',
    ],
    'deps': [],
  },
  {
    'name': 'pbkdf2',
    'sources': [
      'mod/pbkdf2.mod/pbkdf2.c',
      'mod/pbkdf2.mod/tclpbkdf2.c',
    ],
    'deps': [],
  },
  {
    'name': 'seen',
    'sources': ['mod/seen.mod/seen.c'],
    'deps': [],
  },
  {
    'name': 'server',
    'sources': [
      'mod/server.mod/cmdsserv.c',
      'mod/server.mod/isupport.c',
      'mod/server.mod/sasl.c',
      'mod/server.mod/server.c',
      'mod/server.mod/servmsg.c',
      'mod/server.mod/tclisupport.c',
      'mod/server.mod/tclserv.c',
    ],
    'deps': [],   # tls_dep added per-module below if found
  },
  {
    'name': 'share',
    'sources': [
      'mod/share.mod/share.c',
      'mod/share.mod/uf_features.c',
    ],
    'deps': [],
  },
  {
    'name': 'transfer',
    'sources': [
      'mod/transfer.mod/tcltransfer.c',
      'mod/transfer.mod/transfer.c',
      'mod/transfer.mod/transferfstat.c',
      'mod/transfer.mod/transferqueue.c',
    ],
    'deps': [],
  },
  {
    'name': 'twitch',
    'sources': ['mod/twitch.mod/twitch.c'],
    'deps': [],
  },
  {
    'name': 'uptime',
    'sources': ['mod/uptime.mod/uptime.c'],
    'deps': [],
  },
  {
    'name': 'webui',
    'sources': ['mod/webui.mod/webui.c'],
    'deps': [],   # tls_dep added per-module below if found
  },
  {
    'name': 'woobie',
    'sources': ['mod/woobie.mod/woobie.c'],
    'deps': [],
  },
]

# Compress module — only if zlib found
if have_zlib
  module_defs += [{
    'name': 'compress',
    'sources': [
      'mod/compress.mod/compress.c',
      'mod/compress.mod/tclcompress.c',
    ],
    'deps': [zlib_dep],
  }]
endif

# Python module — only if Python 3.8+ found
if have_python
  module_defs += [{
    'name': 'python',
    'sources': [
      'mod/python.mod/pycmds.c',
      'mod/python.mod/python.c',
      'mod/python.mod/tclpython.c',
    ],
    'deps': [python3.dependency()],
  }]
endif

# -------------------------------------------------------------------------
# Module compile flags (shared by all modules)
# -------------------------------------------------------------------------
module_cargs = core_cargs + [
  '-DMAKING_MODS',
]

module_inc = [top_inc, src_inc, include_directories('mod')]

# -------------------------------------------------------------------------
# Static build: compile modules as objects, link into binary
# -------------------------------------------------------------------------
if opt_static
  static_mod_sources = []
  foreach m : module_defs
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

  # Build each module
  foreach m : module_defs
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
install_subdir('../scripts',  install_dir: get_option('datadir') / 'eggdrop',
  strip_directory: true)
install_subdir('../help',     install_dir: get_option('datadir') / 'eggdrop',
  strip_directory: true)
install_subdir('../language', install_dir: get_option('datadir') / 'eggdrop',
  strip_directory: true)
install_data('../eggdrop.conf',
  install_dir: get_option('datadir') / 'eggdrop')
install_data('../eggdrop-basic.conf',
  install_dir: get_option('datadir') / 'eggdrop')
