project('eggdrop', 'c',
  version: '1.10.1',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=gnu99',
    'warning_level=1',
    'b_pie=false',
  ],
  meson_version: '>=0.57.0',
)

cc = meson.get_compiler('c')

# -------------------------------------------------------------------------
# Build options
# -------------------------------------------------------------------------
opt_ipv6    = get_option('ipv6')
opt_tls     = get_option('tls')
opt_tdns    = get_option('tdns')
opt_python  = get_option('python')
opt_debug   = get_option('egg-debug')
opt_handlen = get_option('handlen')
opt_static  = get_option('static-modules')
opt_exec    = get_option('eggexec')

# -------------------------------------------------------------------------
# Configuration data (generates config.h)
# -------------------------------------------------------------------------
cdata = configuration_data()

cdata.set_quoted('PACKAGE',         'eggdrop')
cdata.set_quoted('PACKAGE_NAME',    'Eggdrop')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_BUGREPORT', 'bugs@eggheads.org')
cdata.set_quoted('PACKAGE_URL',     'https://www.eggheads.org')
cdata.set('VERSION', meson.project_version())
cdata.set('HANDLEN', opt_handlen)

# OS / platform detection
host_system = host_machine.system()
if host_system == 'darwin'
  cdata.set('EGG_DARWIN_BUNDLE', 1)
elif host_system == 'cygwin' or host_system == 'windows'
  cdata.set('CYGWIN_HACKS', 1)
endif

# -------------------------------------------------------------------------
# Required headers
# -------------------------------------------------------------------------
req_headers = [
  'stdint.h', 'inttypes.h', 'stddef.h', 'stdlib.h', 'stdio.h',
  'string.h', 'strings.h', 'memory.h', 'unistd.h', 'fcntl.h',
  'dirent.h', 'sys/types.h', 'sys/stat.h', 'sys/time.h',
  'sys/socket.h', 'netinet/in.h', 'netinet/in6.h', 'arpa/inet.h',
  'arpa/nameser.h', 'netdb.h', 'resolv.h', 'dlfcn.h',
]
foreach h : req_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

# struct sockaddr_in6
if cc.has_member('struct sockaddr_in6', 'sin6_addr',
    prefix: '#include <netinet/in.h>')
  cdata.set('HAVE_STRUCT_SOCKADDR_IN6', 1)
endif

# struct in6_addr
if cc.has_type('struct in6_addr', prefix: '#include <netinet/in.h>')
  cdata.set('HAVE_STRUCT_IN6_ADDR', 1)
endif

# in6addr_any / in6addr_loopback (extern constants)
if cc.has_header_symbol('netinet/in.h', 'in6addr_any')
  cdata.set('HAVE_IN6ADDR_ANY', 1)
endif
if cc.has_header_symbol('netinet/in.h', 'in6addr_loopback')
  cdata.set('HAVE_IN6ADDR_LOOPBACK', 1)
endif

# -------------------------------------------------------------------------
# Required functions / symbols
# -------------------------------------------------------------------------
req_funcs = [
  'strlcpy', 'explicit_bzero', 'arc4random', 'arc4random_buf',
  'inet_aton', 'inet_pton', 'inet_ntop',
  'getaddrinfo', 'getnameinfo', 'freeaddrinfo',
  'snprintf', 'vsnprintf',
  'getentropy', 'getrandom',
  'pledge', 'unveil',
]
foreach f : req_funcs
  if cc.has_function(f)
    cdata.set('HAVE_' + f.to_upper(), 1)
  endif
endforeach

# base64_encode / base64_decode - some platforms have them
foreach f : ['base64_encode', 'base64_decode']
  if cc.has_function(f)
    cdata.set('HAVE_' + f.to_upper(), 1)
  endif
endforeach

# -------------------------------------------------------------------------
# Tcl — required
# -------------------------------------------------------------------------
# Try pkg-config, then cmake, then manual library search
tcl_dep = dependency('tcl', version: '>=8.6', required: false)
if not tcl_dep.found()
  tcl_dep = dependency('TCL', version: '>=8.6', required: false, method: 'cmake')
endif
if not tcl_dep.found()
  # Manual fallback: search standard locations
  tcl_lib = cc.find_library('tcl8.6',
    dirs: [
      '/usr/lib', '/usr/local/lib',
      '/usr/lib/x86_64-linux-gnu',
      '/usr/lib/aarch64-linux-gnu',
    ],
    required: false)
  if not tcl_lib.found()
    tcl_lib = cc.find_library('tcl', required: true)
  endif
  # Find tcl.h include directory
  tcl_h = cc.find_header('tcl.h',
    dirs: [
      '/usr/include/tcl8.6',
      '/usr/local/include/tcl8.6',
      '/usr/include',
      '/usr/local/include',
    ],
    required: true)
  tcl_inc = include_directories('/usr/include/tcl8.6')
  tcl_dep = declare_dependency(dependencies: tcl_lib,
                               include_directories: tcl_inc)
endif
cdata.set('TCL_VERSION', '"8.6"')

# -------------------------------------------------------------------------
# TLS / OpenSSL — optional
# -------------------------------------------------------------------------
tls_dep = dependency('openssl', version: '>=1.0.0', required: opt_tls)
have_tls = tls_dep.found()
if have_tls
  cdata.set('HAVE_OPENSSL', 1)
  cdata.set('TLS', 1)
  cdata.set('HAVE_TLS', 1)
endif

# -------------------------------------------------------------------------
# IPv6
# -------------------------------------------------------------------------
if opt_ipv6 and cdata.has('HAVE_STRUCT_SOCKADDR_IN6')
  cdata.set('IPV6', 1)
  cdata.set('HAVE_IPV6', 1)
endif

# -------------------------------------------------------------------------
# Threaded DNS
# -------------------------------------------------------------------------
thread_dep = dependency('threads', required: false)
have_tdns = opt_tdns and thread_dep.found()
if have_tdns
  cdata.set('EGG_TDNS', 1)
endif

# -------------------------------------------------------------------------
# zlib — optional (for compress module)
# -------------------------------------------------------------------------
zlib_dep = dependency('zlib', required: false)
have_zlib = zlib_dep.found()

# -------------------------------------------------------------------------
# epoll — Linux kernel ≥ 2.6 (glibc sys/epoll.h)
# When present the main event loop uses epoll_wait() instead of select().
# -------------------------------------------------------------------------
have_epoll = cc.has_header('sys/epoll.h')
if have_epoll
  cdata.set('HAVE_EPOLL', 1)
  message('epoll detected — using epoll back-end')
else
  message('epoll not found — falling back to select()')
endif

# -------------------------------------------------------------------------
# kqueue — BSD / macOS (sys/event.h)
# Used when epoll is unavailable (i.e. on macOS, FreeBSD, OpenBSD, NetBSD).
# -------------------------------------------------------------------------
have_kqueue = cc.has_header('sys/event.h')
if have_kqueue
  cdata.set('HAVE_KQUEUE', 1)
  if not have_epoll
    message('kqueue detected — using kqueue back-end')
  else
    message('kqueue detected (epoll preferred on this platform)')
  endif
else
  message('kqueue not found')
endif

# -------------------------------------------------------------------------
# accept4 — Linux ≥ 2.6.28, glibc ≥ 2.10
# Atomically sets SOCK_NONBLOCK | SOCK_CLOEXEC on the accepted socket,
# avoiding two racy fcntl() calls after plain accept().
# -------------------------------------------------------------------------
if cc.has_function('accept4', prefix: '#define _GNU_SOURCE\n#include <sys/socket.h>')
  cdata.set('HAVE_ACCEPT4', 1)
endif

# SOCK_CLOEXEC / SOCK_NONBLOCK — available on Linux ≥ 2.6.23
if cc.has_header_symbol('sys/socket.h', 'SOCK_CLOEXEC',
    prefix: '#define _GNU_SOURCE')
  cdata.set('HAVE_SOCK_CLOEXEC', 1)
endif

# -------------------------------------------------------------------------
# sendfile — zero-copy file-to-socket (Linux ≥ 2.2, sys/sendfile.h)
# Used by transfer.mod to avoid userspace copy during DCC file sends.
# -------------------------------------------------------------------------
if cc.has_header('sys/sendfile.h')
  cdata.set('HAVE_SYS_SENDFILE_H', 1)
  if cc.has_function('sendfile', prefix: '#include <sys/sendfile.h>')
    cdata.set('HAVE_SENDFILE', 1)
    message('sendfile() detected — zero-copy DCC transfers enabled')
  else
    message('sendfile() not found — using read/write for DCC')
  endif
else
  message('sys/sendfile.h not found — using read/write for DCC')
endif

# -------------------------------------------------------------------------
# liburing — io_uring (Linux ≥ 5.1)
# When available, the io_uring back-end is preferred over epoll.
# -------------------------------------------------------------------------
uring_dep = dependency('liburing', required: false)
have_uring = uring_dep.found()
if have_uring
  cdata.set('HAVE_LIBURING', 1)
  message('liburing detected — using io_uring back-end')
else
  message('liburing not found — io_uring back-end disabled')
endif

# -------------------------------------------------------------------------
# Python — optional (for python module)
# -------------------------------------------------------------------------
pymod = import('python')
python3 = pymod.find_installation('python3', required: opt_python)
have_python = python3.found()
if have_python
  py_ver = python3.language_version()
  if not py_ver.version_compare('>=3.8')
    if opt_python.enabled()
      error('Python >= 3.8 required, found ' + py_ver)
    endif
    have_python = false
  endif
endif

# -------------------------------------------------------------------------
# System libraries
# -------------------------------------------------------------------------
dl_dep     = cc.find_library('dl',     required: false)
resolv_dep = cc.find_library('resolv', required: false)
nsl_dep    = cc.find_library('nsl',    required: false)
m_dep      = cc.find_library('m',      required: false)

# b64_ntop / b64_pton — BSD/glibc base64 (part of libresolv on Linux).
# When present, set HAVE_BASE64 so our compat/base64.c is skipped.
if cc.has_function('b64_ntop', dependencies: resolv_dep,
    prefix: '#include <resolv.h>')
  cdata.set('HAVE_BASE64', 1)
endif

# Module loading method
if cc.has_function('dlopen', dependencies: dl_dep)
  cdata.set('HAVE_DLOPEN', 1)
  cdata.set('DLOPEN_1', 1)
  cdata.set('MODULES_OK', 1)
  cdata.set('MOD_USE_DL', 1)
elif cc.has_header('dl.h') and cc.has_function('shl_load')
  cdata.set('HAVE_SHL_LOAD', 1)
  cdata.set('MODULES_OK', 1)
  cdata.set('MOD_USE_SHL', 1)
endif

# Module file extension
if host_system == 'darwin'
  mod_ext = 'dylib'
  cdata.set_quoted('EGG_MOD_EXT', 'dylib')
elif host_system == 'windows' or host_system == 'cygwin'
  mod_ext = 'dll'
  cdata.set_quoted('EGG_MOD_EXT', 'dll')
else
  mod_ext = 'so'
  cdata.set_quoted('EGG_MOD_EXT', 'so')
endif

# Debug flags
if opt_debug
  cdata.set('DEBUG', 1)
  add_project_arguments('-g', '-DDEBUG', language: 'c')
endif

# -------------------------------------------------------------------------
# Write config.h
# -------------------------------------------------------------------------
config_h = configure_file(output: 'config.h', configuration: cdata)
config_inc = include_directories('.')

# -------------------------------------------------------------------------
# Global include directories
# -------------------------------------------------------------------------
top_inc = include_directories('.')
src_inc = include_directories('src')
mod_inc = include_directories('src/mod')

# -------------------------------------------------------------------------
# Recurse into src/
# -------------------------------------------------------------------------
subdir('src')

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
if have_uring
  io_backend = 'io_uring'
elif have_epoll
  io_backend = 'epoll'
elif have_kqueue
  io_backend = 'kqueue'
else
  io_backend = 'select'
endif

summary({
  'Prefix':         get_option('prefix'),
  'IPv6':           opt_ipv6,
  'TLS/OpenSSL':    have_tls,
  'Threaded DNS':   have_tdns,
  'Python module':  have_python,
  'Compress module': have_zlib,
  'Static modules': opt_static,
  'Executable':     opt_exec,
  'HANDLEN':        opt_handlen,
  'I/O backend':    io_backend,
}, section: 'Eggdrop configuration')
