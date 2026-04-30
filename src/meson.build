# =========================================================================
# src/meson.build — eggdrop core binary + all modules
# =========================================================================

fs = import('fs')

# -------------------------------------------------------------------------
# Compat and MD5 are now absorbed into libop (libop_dep).
# compat_dep and md5_dep are kept as aliases so nothing else needs changing.
# -------------------------------------------------------------------------
compat_dep = libop_dep
md5_dep    = libop_dep

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
  'egg_commio.c',
  'language.c',
  'main.c',
  'match.c',
  'misc.c',
  'misc_file.c',
  'script.c',
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

# -------------------------------------------------------------------------
# Core compile flags
# -------------------------------------------------------------------------
core_cargs = [
  '-DHAVE_CONFIG_H',
  '-DEGG_VERSION="@0@"'.format(meson.project_version()),
  '-DHANDLEN=@0@'.format(opt_handlen),
  '-DEGG_DATADIR="@0@"'.format(get_option('prefix') / get_option('datadir') / 'eggdrop'),
  '-DEGG_MODDIR="@0@"'.format(get_option('prefix') / get_option('libdir') / 'eggdrop' / meson.project_version()),
  # IntFunc (typedef int (*IntFunc)()) is intentional type-erasure: functions are
  # always called through explicit casts back to the real type.  C23 changed
  # the meaning of () from "unspecified args" to (void), making all implicit
  # function-pointer conversions into hard errors.  Suppress for this pattern.
  '-Wno-incompatible-pointer-types',
]

if have_tls
  core_cargs += ['-include', 'wolfssl/options.h']  # load system wolfSSL config
endif

# Generic -DDEBUG/-g flags are applied globally via add_project_arguments()
# in the top meson.build.

# -------------------------------------------------------------------------
# All link dependencies for the main binary
# -------------------------------------------------------------------------
eggdrop_deps = [
  libop_dep,   # includes compat and MD5 (merged into libop)
]
if have_tcl
  eggdrop_deps = [tcl_dep] + eggdrop_deps
endif

if have_tls
  eggdrop_deps += tls_dep
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
  {'name': 'dns',     'sources': ['mod/dns.mod/dns.c'],              'deps': []},
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

module_inc = [top_inc, src_inc, include_directories('mod'), libop_inc]

# Minimal system deps for modules.  Modules resolve eggdrop, compat, md5,
# and tcl symbols at dlopen() time from the already-loaded main binary
# (export_dynamic: true); they must not re-link those static archives.
mod_system_deps = []
foreach _d : [dl_dep, nsl_dep, m_dep, ws2_dep, mswsock_dep]
  if _d.found()
    mod_system_deps += _d
  endif
endforeach
# Modules need the Tcl include path (for lush.h) but must not re-link
# libtcl — that symbol is exported by the main binary at runtime.
if have_tcl
  mod_system_deps += tcl_dep.partial_dependency(includes: true, compile_args: true)
endif

# libeggres removed — res.c is compiled only as part of the dns module
# (dns.mod/dns.c #includes res.c in a unity build).  The standalone lib
# served no purpose once the use-res-dns option always selects res.c.

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
    include_directories: [top_inc, src_inc, mod_inc, libop_inc],
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
    include_directories: [top_inc, src_inc, mod_inc, libop_inc],
    c_args: core_cargs,
    dependencies: eggdrop_deps,
    export_dynamic: true,   # allow modules to call back into binary
    install: true,
  )

  # Install path for modules
  modules_dir = get_option('libdir') / 'eggdrop' / meson.project_version()

  # Build each enabled module
  foreach m : enabled_module_defs
    mod_deps = mod_system_deps + m['deps']
    # Per-module conditional dependencies
    if m['name'] == 'dns' and resolv_dep.found()
      mod_deps += resolv_dep
    endif
    if m['name'] in ['dns', 'server', 'webui'] and have_tls
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
      # Modules are unity builds (one TU each) — LTO adds link-time
      # code-gen overhead with no cross-TU inlining benefit.
      override_options: ['b_lto=false'],
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
install_subdir(_root / 'language', install_dir: _ddir / 'language', strip_directory: true)
# Module-specific language files (console, notes, transfer, filesys, assoc)
foreach _mod : ['assoc', 'console', 'filesys', 'notes', 'transfer']
  _modlang = meson.current_source_dir() / 'mod' / _mod + '.mod' / 'language'
  if fs.is_dir(_modlang)
    install_subdir(_modlang, install_dir: _ddir / 'language', strip_directory: true)
  endif
endforeach
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
