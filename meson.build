project('eggdrop', 'c',
  version: '1.10.1',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=gnu23',
    'warning_level=1',           # -Wall; level 2 adds -Wextra (6k+ cast-fn-type hits)
    'b_pie=true',                # Position-Independent Executable — enables full ASLR
    'buildtype=release',         # -O3 + strip; use --buildtype=debugoptimized for -O2 + -g
    'b_lto=true',                # cross-file inlining + dead code elimination
    'b_lto_threads=0',           # 0 = use all available CPU threads for LTO linking
    'b_ndebug=if-release',       # strip assert() in release builds
  ],
  meson_version: '>=0.60.0',    # b_lto_threads requires 0.57; 0.60 for stable PCH API
)

cc = meson.get_compiler('c')

# -------------------------------------------------------------------------
# Build options
# -------------------------------------------------------------------------
opt_tcl       = get_option('tcl')
opt_ipv6      = get_option('ipv6')
opt_native    = get_option('native-opt')
opt_tls       = get_option('tls')
opt_python    = get_option('python')
opt_debug     = get_option('egg-debug')
opt_handlen   = get_option('handlen')
opt_static    = get_option('static-modules')
opt_exec      = get_option('eggexec')
opt_hardening = get_option('hardening')

# -------------------------------------------------------------------------
# DATECODE — Unix timestamp of the most recent git commit.
# Passed as a compile-time constant for version.c (op_build_info).
# Falls back to 0 when git is unavailable (release tarball builds).
# -------------------------------------------------------------------------
_datecode_r = run_command('git', 'log', '-1', '--pretty=format:%ct', check: false)
_datecode   = _datecode_r.returncode() == 0 ? _datecode_r.stdout().strip() : '0'
add_project_arguments('-DDATECODE=' + _datecode + 'UL', language: 'c')

# -------------------------------------------------------------------------
# Configuration data (generates config.h)
# -------------------------------------------------------------------------
cdata = configuration_data()

cdata.set_quoted('PACKAGE',         'eggdrop')
cdata.set_quoted('PACKAGE_NAME',    'Eggdrop')
cdata.set_quoted('PACKAGE_VERSION', meson.project_version())
cdata.set_quoted('BRANDING_NAME',    meson.project_name())
cdata.set_quoted('BRANDING_VERSION', meson.project_version())
cdata.set_quoted('PACKAGE_BUGREPORT', 'bugs@eggheads.org')
cdata.set_quoted('PACKAGE_URL',     'https://www.eggheads.org')
cdata.set('VERSION', meson.project_version())
cdata.set('HANDLEN', opt_handlen)

# OS / platform detection
host_system = host_machine.system()
is_native_windows = (host_system == 'windows')
is_cygwin         = (host_system == 'cygwin')

if host_system == 'darwin'
  cdata.set('EGG_DARWIN_BUNDLE', 1)
elif is_native_windows
  # Native Windows (MinGW / MSVC): IOCP event loop, Winsock2.
  # Cygwin is a POSIX emulation layer — it does not expose Win32 IOCP
  # APIs, so it takes the plain POSIX path and uses select() as its
  # I/O backend.  No special define is set for Cygwin.
  cdata.set('EGG_NATIVE_WIN32', 1)
  cdata.set('HAVE_IOCP', 1)
  message('Native Windows build — IOCP backend enabled')
endif

# -------------------------------------------------------------------------
# Required headers
# -------------------------------------------------------------------------
req_headers = [
  'stdint.h', 'inttypes.h', 'stddef.h', 'stdlib.h', 'stdio.h',
  'string.h', 'strings.h', 'memory.h', 'unistd.h', 'fcntl.h',
  'dirent.h', 'sys/types.h', 'sys/stat.h', 'sys/time.h',
  'sys/uio.h', 'sys/socket.h', 'netinet/in.h', 'netinet/in6.h', 'arpa/inet.h',
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
  'base64_encode', 'base64_decode',
]
foreach f : req_funcs
  if cc.has_function(f)
    cdata.set('HAVE_' + f.to_upper(), 1)
  endif
endforeach


# -------------------------------------------------------------------------
# Tcl — optional (enabled by default; disable with -Dtcl=disabled)
# -------------------------------------------------------------------------
# Try pkg-config (tcl or tcl9.0), then cmake, then manual library search.
# Homebrew on macOS installs Tcl 9.0 as a keg-only formula; PKG_CONFIG_PATH
# must include $(brew --prefix tcl-tk)/lib/pkgconfig for pkg-config to find
# tcl.pc there.  Both 'tcl' and 'tcl9.0' names are tried for robustness.
#
# When Tcl is not found (or explicitly disabled), HAVE_TCL is not defined and
# eggdrop builds without any Tcl scripting support.  All existing Tcl scripts
# remain compatible when Tcl is present — this only affects buildability.
tcl_dep = dependency('', required: false)  # sentinel: not-found
if opt_tcl.allowed()
  tcl_dep = dependency('tcl', version: '>=8.6', required: false)
  if not tcl_dep.found()
    tcl_dep = dependency('tcl9.0', required: false)
  endif
  if not tcl_dep.found()
    tcl_dep = dependency('TCL', version: '>=8.6', required: false, method: 'cmake')
  endif
  if not tcl_dep.found()
    # Manual fallback: search standard and Homebrew locations.
    # Homebrew installs Tcl as a keg-only package; the library may be named
    # libtcl9.0 (Tcl 9.0) or libtcl8.6 (Tcl 8.6).
    _tcl_lib_dirs = [
      '/usr/lib', '/usr/local/lib',
      '/usr/lib/x86_64-linux-gnu',
      '/usr/lib/aarch64-linux-gnu',
      '/opt/homebrew/opt/tcl-tk/lib',
      '/usr/local/opt/tcl-tk/lib',
    ]
    tcl_lib = cc.find_library('tcl9.0', dirs: _tcl_lib_dirs, required: false)
    if not tcl_lib.found()
      tcl_lib = cc.find_library('tcl8.6', dirs: _tcl_lib_dirs, required: false)
    endif
    if not tcl_lib.found()
      tcl_lib = cc.find_library('tcl', dirs: _tcl_lib_dirs, required: opt_tcl)
    endif
    if tcl_lib.found()
      # Find tcl.h; Homebrew Tcl 9.0 puts headers in include/tcl9.0/,
      # Tcl 8.6 in include/tcl8.6/.
      _tcl_inc_dirs = [
        '/opt/homebrew/opt/tcl-tk/include/tcl9.0',
        '/opt/homebrew/opt/tcl-tk/include/tcl8.6',
        '/opt/homebrew/opt/tcl-tk/include',
        '/usr/local/opt/tcl-tk/include/tcl9.0',
        '/usr/local/opt/tcl-tk/include/tcl8.6',
        '/usr/local/opt/tcl-tk/include',
        '/usr/include/tcl9.0',
        '/usr/include/tcl8.6',
        '/usr/local/include/tcl9.0',
        '/usr/local/include/tcl8.6',
        '/usr/include',
        '/usr/local/include',
      ]
      tcl_h = cc.find_header('tcl.h', dirs: _tcl_inc_dirs, required: opt_tcl)
      if tcl_h.found()
        # We pass all candidate dirs as include paths; the compiler finds the
        # right one.  Non-existent dirs are silently ignored by the compiler.
        tcl_inc = include_directories(
          '/opt/homebrew/opt/tcl-tk/include/tcl9.0',
          '/opt/homebrew/opt/tcl-tk/include/tcl8.6',
          '/opt/homebrew/opt/tcl-tk/include',
          '/usr/local/opt/tcl-tk/include/tcl9.0',
          '/usr/local/opt/tcl-tk/include/tcl8.6',
          '/usr/local/opt/tcl-tk/include',
          '/usr/include/tcl9.0',
          '/usr/include/tcl8.6',
          '/usr/local/include/tcl9.0',
          '/usr/local/include/tcl8.6',
        )
        tcl_dep = declare_dependency(dependencies: tcl_lib,
                                     include_directories: tcl_inc)
      endif
    endif
  endif
endif

have_tcl = tcl_dep.found()
if have_tcl
  # TCL_VERSION is defined by tcl.h itself; do not define it in config.h to
  # avoid a macro redefinition conflict when Tcl 9.x headers are used.
  cdata.set('HAVE_TCL', 1)
  message('Tcl scripting: enabled')
else
  message('Tcl scripting: disabled (build without -DHAVE_TCL)')
endif

# -------------------------------------------------------------------------
# TLS / opssl — bundled TLS library (no external TLS dependency needed)
# opssl is built as a Meson subproject from subprojects/opssl/
# -------------------------------------------------------------------------
opssl_dep = dependency('', required: false)  # sentinel
if opt_tls.allowed()
  _opssl_sub = subproject('opssl', required: opt_tls)
  if _opssl_sub.found()
    opssl_dep = _opssl_sub.get_variable('opssl_dep')
  endif
endif
tls_dep  = opssl_dep     # alias used throughout src/meson.build
have_tls = opssl_dep.found()
have_ssl = have_tls       # alias used by libop subdir

if have_tls
  cdata.set('HAVE_OPSSL', 1)
  cdata.set('TLS', 1)
  cdata.set('HAVE_TLS', 1)
  message('TLS: opssl found — TLS enabled')
else
  message('TLS: opssl not found — TLS disabled')
  if opt_tls.enabled()
    error('opssl required (-Dtls=enabled) but subproject build failed')
  endif
endif

# -------------------------------------------------------------------------
# IPv6
# -------------------------------------------------------------------------
if opt_ipv6 and cdata.has('HAVE_STRUCT_SOCKADDR_IN6')
  cdata.set('IPV6', 1)
  cdata.set('HAVE_IPV6', 1)
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
  cdata.set('HAVE_EPOLL_CTL', 1)   # libop commio alias
  message('epoll detected — using epoll back-end')
else
  message('epoll not found — falling back to select()')
endif

# -------------------------------------------------------------------------
# kqueue — BSD / macOS (sys/event.h + kqueue() function)
# Used when epoll is unavailable (i.e. on macOS, FreeBSD, OpenBSD, NetBSD).
# -------------------------------------------------------------------------
have_kqueue = cc.has_header('sys/event.h') and cc.has_function('kqueue',
    prefix: '#include <sys/types.h>\n#include <sys/event.h>\n#include <sys/time.h>')
if have_kqueue
  cdata.set('HAVE_KQUEUE', 1)
  cdata.set('HAVE_KEVENT', 1)      # libop commio alias
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

# writev — scatter-gather I/O (POSIX, virtually universal)
if cc.has_function('writev', prefix: '#include <sys/uio.h>')
  cdata.set('HAVE_WRITEV', 1)
endif

# -------------------------------------------------------------------------
# sendfile — zero-copy file-to-socket
# Linux: sys/sendfile.h, sendfile(out_fd, in_fd, offset, count)
# FreeBSD/macOS: sys/socket.h, sendfile(in_fd, out_fd, offset, nbytes, hdtr, sbytes, flags)
# -------------------------------------------------------------------------
if cc.has_header('sys/sendfile.h')
  cdata.set('HAVE_SYS_SENDFILE_H', 1)
  if cc.has_function('sendfile', prefix: '#include <sys/sendfile.h>')
    cdata.set('HAVE_SENDFILE', 1)
    message('sendfile() detected (Linux) — zero-copy DCC transfers enabled')
  else
    message('sendfile() not found — using read/write for DCC')
  endif
elif cc.has_function('sendfile', prefix: '#include <sys/types.h>\n#include <sys/socket.h>\n#include <sys/uio.h>')
  cdata.set('HAVE_BSD_SENDFILE', 1)
  message('sendfile() detected (BSD) — zero-copy DCC transfers enabled')
else
  message('sendfile() not found — using read/write for DCC')
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

# Windows-native Winsock2 + MsWSock (required for IOCP / WSARecv / WSASend)
if is_native_windows
  ws2_dep     = cc.find_library('ws2_32',  required: true)
  mswsock_dep = cc.find_library('mswsock', required: true)
else
  ws2_dep     = dependency('', required: false)
  mswsock_dep = dependency('', required: false)
endif

# b64_ntop / b64_pton — BSD/glibc base64 (part of libresolv on Linux).
# Only use the system version when b64_ntop is a real public symbol, not
# a macro alias (e.g. glibc defines "#define b64_ntop __b64_ntop" in
# resolv.h, making modules incorrectly depend on the private __b64_ntop
# symbol). When it is a macro, fall through to our compat/base64.c.
if cc.compiles('#include <resolv.h>\n#ifdef b64_ntop\n#error macro\n#endif',
    name: 'b64_ntop is not a macro') and cc.has_function('b64_ntop',
    dependencies: resolv_dep, prefix: '#include <resolv.h>')
  cdata.set('HAVE_BASE64', 1)
endif

# Module loading method
if is_native_windows
  # Native Windows: LoadLibrary() / GetProcAddress() — no dlopen
  cdata.set('MODULES_OK', 1)
  cdata.set('MOD_USE_WIN32', 1)
elif cc.has_function('dlopen', dependencies: dl_dep)
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

# ---------------------------------------------------------------------------
# Compiler / linker flag optimizations
# ---------------------------------------------------------------------------

# -pipe: use pipes between compiler stages instead of temp files.
# Speeds up parallel builds on all platforms.
if cc.has_argument('-pipe')
  add_project_arguments('-pipe', language: 'c')
endif

# -fno-strict-aliasing: eggdrop uses void*/char* casts that technically
# violate strict-aliasing rules; disable the optimisation to prevent UB.
if cc.has_argument('-fno-strict-aliasing')
  add_project_arguments('-fno-strict-aliasing', language: 'c')
endif

# -Wl,--as-needed: only link libraries that are actually referenced,
# reducing startup time and avoiding spurious dependencies.
if not is_native_windows
  if cc.has_link_argument('-Wl,--as-needed')
    add_project_link_arguments('-Wl,--as-needed', language: 'c')
  endif
endif

# -march=native / -mcpu=native: tune for the exact CPU running the build.
# Non-portable — disable when cross-compiling or building for distribution.
#
# Flag selection by architecture:
#   ARM / AArch64 / PowerPC  →  -mcpu=native  (sets core type + tune)
#   x86 / x86_64 / RISC-V / MIPS / s390x / everything else  →  -march=native
#
# cc.has_argument() probes the compiler so the build never silently passes
# an unsupported flag.
_native_summary = 'off'
if opt_native
  _cpu = host_machine.cpu_family()
  if _cpu in ['aarch64', 'arm', 'ppc', 'ppc64']
    _tune_flag = '-mcpu=native'
  else
    _tune_flag = '-march=native'
  endif
  if cc.has_argument(_tune_flag)
    add_project_arguments(_tune_flag, language: 'c')
    _native_summary = _tune_flag + '  (cpu_family=' + _cpu + ')'
  else
    _native_summary = 'unsupported by compiler'
    warning('native-opt: ' + _tune_flag + ' not supported by this compiler; skipped')
  endif
endif

# ---------------------------------------------------------------------------
# Security hardening flags  (disable with -Dhardening=false)
# ---------------------------------------------------------------------------
if opt_hardening

# -fstack-protector-strong: insert stack canaries for functions with arrays,
# pointers to locals, or address-taken frames.  Catches stack overflows at
# runtime; '-strong' is more selective (less overhead) than '-all'.
# (GCC >= 4.9, Clang >= 3.4)
if cc.has_argument('-fstack-protector-strong')
  add_project_arguments('-fstack-protector-strong', language: 'c')
endif

# -fstack-clash-protection: touch each stack page sequentially so the kernel
# guard page cannot be skipped by a large alloca.
# (GCC >= 8, Clang >= 11)
if cc.has_argument('-fstack-clash-protection')
  add_project_arguments('-fstack-clash-protection', language: 'c')
endif

# Control-flow integrity — architecture-specific.
#
# x86/x86_64: Intel CET (Control-Flow Enforcement Technology).
# -fcf-protection=full inserts ENDBR instructions and enables indirect-branch
# tracking + shadow stack (IBT + SHSTK).  (GCC >= 8, Clang >= 7)
#
# AArch64: ARM Branch Target Identification + Pointer Authentication.
# -mbranch-protection=standard enables BTI (landing pads for indirect branches)
# and PAC (signed return addresses).  Equivalent hardening to Intel CET.
# (GCC >= 9, Clang >= 8)
if host_machine.cpu_family() in ['x86', 'x86_64']
  if cc.has_argument('-fcf-protection=full')
    add_project_arguments('-fcf-protection=full', language: 'c')
  endif
elif host_machine.cpu_family() == 'aarch64'
  if cc.has_argument('-mbranch-protection=standard')
    add_project_arguments('-mbranch-protection=standard', language: 'c')
  endif
endif

# _FORTIFY_SOURCE=2: glibc runtime buffer-overflow detection in common library
# functions (memcpy, strcpy, sprintf, …).  Requires at least -O1; skip on
# plain or unoptimised debug builds where -O0 is implied.
# Undefine first in case the compiler/distro already defines a lower level.
_bt = get_option('buildtype')
if _bt != 'plain' and _bt != 'debug'
  add_project_arguments('-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=2', language: 'c')
endif

# -Wformat-security: warn when a non-literal format string with no additional
# arguments is passed to a printf-family function (potential injection vector).
# Included in -Wall but listed explicitly for clarity.
# Note: -Wformat=2 is intentionally NOT used — it adds -Wformat-nonliteral which
# produces 238 spurious warnings from eggdrop's language-string messaging pattern.
if cc.has_argument('-Wformat-security')
  add_project_arguments('-Wformat-security', language: 'c')
endif

# Full RELRO: ask the dynamic linker to map all relocations before dropping
# privileges, then remap the GOT read-only.  Prevents GOT-overwrite exploits.
# -z relro marks the section; -z now forces eager binding (required for full).
# Negligible startup overhead on modern kernels.
if not is_native_windows
  foreach _rl : ['-Wl,-z,relro', '-Wl,-z,now']
    if cc.has_link_argument(_rl)
      add_project_link_arguments(_rl, language: 'c')
    endif
  endforeach
endif

# -Wl,-z,noexecstack: explicitly mark the stack non-executable.
# Most modern toolchains set this by default, but being explicit prevents
# any accidental override from an assembled object file.
if not is_native_windows
  if cc.has_link_argument('-Wl,-z,noexecstack')
    add_project_link_arguments('-Wl,-z,noexecstack', language: 'c')
  endif
endif

# -fno-plt: call external functions directly through the GOT instead of via
# PLT trampolines.  Eliminates one layer of indirection per external call and
# shrinks the attack surface (no writable PLT entries).  Requires -z now so
# all GOT slots are resolved at startup before the first call.
# (GCC >= 6, Clang >= 3.8)
if cc.has_argument('-fno-plt')
  add_project_arguments('-fno-plt', language: 'c')
endif

# -fno-common: error on tentative definitions (multiply-defined globals).
# Has been the GCC default since GCC 10; explicit here for older toolchains
# and to catch latent multi-definition bugs early.
if cc.has_argument('-fno-common')
  add_project_arguments('-fno-common', language: 'c')
endif

endif # opt_hardening

# ---------------------------------------------------------------------------
# Targeted code-quality warnings
# These are chosen because they catch real bugs in C code without producing
# false positives from eggdrop's existing codebase.
# (warning_level=2 / -Wextra is not used globally: it triggers 6000+
# -Wcast-function-type hits from the module dispatch system by design.)
# ---------------------------------------------------------------------------
foreach _w : [
  '-Wshadow=local',          # local variable shadows an outer variable
  '-Wnull-dereference',      # provable NULL dereference paths
  '-Wimplicit-fallthrough',  # switch case fall-through without annotation
  '-Wduplicated-cond',       # if (a) … else if (a) — always same branch
  '-Wlogical-op',            # logical operators where bitwise was likely intended
  '-Wvla',                   # variable-length arrays (stack size uncontrolled)
  '-Wno-stringop-overread',  # GCC false positive in sha1.c under LTO
  # Note: -Wformat=2 includes -Wformat-nonliteral which triggers 238 false positives
  # from eggdrop's intentional pattern of passing language-file strings as format args.
  # -Wformat-security (included in -Wall) covers the genuine security case.
]
  if cc.has_argument(_w)
    add_project_arguments(_w, language: 'c')
  endif
endforeach

# ---------------------------------------------------------------------------
# Debug / sanitizer flags
# ---------------------------------------------------------------------------
if opt_debug
  cdata.set('DEBUG', 1)
  add_project_arguments('-g', '-DDEBUG', language: 'c')
  # AddressSanitizer + UndefinedBehaviourSanitizer: catch memory errors and
  # UB at runtime.  -fno-omit-frame-pointer gives readable stack traces.
  # Both compiler and linker flags are required.
  _san_flags = []
  foreach _s : ['-fsanitize=address', '-fsanitize=undefined']
    if cc.has_argument(_s)
      _san_flags += [_s]
    endif
  endforeach
  if _san_flags.length() > 0
    _san_flags += ['-fno-omit-frame-pointer']
    add_project_arguments(_san_flags, language: 'c')
    add_project_link_arguments(_san_flags, language: 'c')
    message('egg-debug: ASAN + UBSAN enabled (' + ' '.join(_san_flags) + ')')
  endif
else
  # Release/optimised builds: omitting the frame pointer frees a register.
  if cc.has_argument('-fomit-frame-pointer')
    add_project_arguments('-fomit-frame-pointer', language: 'c')
  endif
endif

# LTO re-analyses warnings at link time; pass through suppression flags.
if cc.has_argument('-Wno-stringop-overread')
  add_project_link_arguments('-Wno-stringop-overread', language: 'c')
endif

# -------------------------------------------------------------------------
# Write config.h
# -------------------------------------------------------------------------
config_h = configure_file(output: 'config.h', configuration: cdata)

# -------------------------------------------------------------------------
# Global include directories
# -------------------------------------------------------------------------
top_inc = include_directories('.')   # also covers generated config.h
src_inc = include_directories('src')
mod_inc = include_directories('src/mod')

# -------------------------------------------------------------------------
# libop — portable data-structure library (subset of ophion's libop)
# -------------------------------------------------------------------------
subdir('libop')

# -------------------------------------------------------------------------
# Recurse into src/
# -------------------------------------------------------------------------
subdir('src')

# -------------------------------------------------------------------------
# Tests
# -------------------------------------------------------------------------
subdir('tests')

# -------------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------------
if have_uring
  _io_backend = 'io_uring'
elif have_epoll
  _io_backend = 'epoll'
elif have_kqueue
  _io_backend = 'kqueue'
elif is_native_windows
  _io_backend = 'iocp'
else
  _io_backend = 'select'
endif
summary({
  'Prefix':          get_option('prefix'),
  'IPv6':            opt_ipv6,
  'TLS/opssl':       have_tls,
  'Async DNS (res.c)': true,
  'Python module':   have_python,
  'Compress module': have_zlib,
  'Static modules':  opt_static,
  'Native CPU opt':  _native_summary,
  'LTO':             get_option('b_lto'),
  'LTO threads':     get_option('b_lto_threads'),
  'Build type':      get_option('buildtype'),
  'PIE':             get_option('b_pie'),
  'Hardening':       opt_hardening
                     ? 'stack-protector, stack-clash, FORTIFY=2, RELRO+NOW, no-plt, no-common'
                     : 'disabled (-Dhardening=false)',
  'Sanitizers':      opt_debug ? 'ASAN + UBSAN (egg-debug=true)' : 'off',
  'Executable':      opt_exec,
  'HANDLEN':         opt_handlen,
  'I/O backend':     _io_backend,
}, section: 'Eggdrop configuration')
