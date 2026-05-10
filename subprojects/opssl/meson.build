project('opssl', 'c',
  version: '1.0.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=c23',
    'warning_level=2',
    'b_pie=true',
    'b_lto=true',
  ],
  meson_version: '>= 0.60.0',
)

cc = meson.get_compiler('c')

# Platform detection
host_system = host_machine.system()
is_linux = host_system == 'linux'
is_bsd = host_system in ['freebsd', 'netbsd', 'openbsd', 'dragonfly']

# Feature options
opt_ktls = get_option('ktls')
opt_postquantum = get_option('postquantum')
opt_session_export = get_option('session_export')

# System dependencies
threads_dep = dependency('threads')
math_dep = cc.find_library('m', required: false)

# libop — opssl is part of the libop ecosystem.
# No pkg-config. Resolved via Meson subproject or parent include path.
#
# libop's configure_file() step requires the host project (ophion) to
# generate libop_config.h. For standalone opssl builds, we provide a
# local stub config and use libop headers only (linking happens at the
# ophion level).
if meson.is_subproject()
  # When opssl is a subproject, libop headers live in the parent project.
  # eggdrop: libop/include   ophion: subprojects/libop/include
  # Check both paths and use whichever exists.
  _root = meson.global_source_root()
  _libop_inc_egg = _root / 'libop' / 'include'
  _libop_inc_oph = _root / 'subprojects' / 'libop' / 'include'
  if import('fs').is_dir(_libop_inc_egg)
    _libop_inc = _libop_inc_egg
  else
    _libop_inc = _libop_inc_oph
  endif
  libop_dep = declare_dependency(
    include_directories: include_directories('compat'),
    compile_args: ['-I' + _libop_inc],
  )
else
  # Standalone build: headers + local stubs (no full libop build)
  libop_stubs = static_library('op_stubs', 'compat/libop_stubs.c',
    include_directories: include_directories('subprojects/libop/include', 'compat'),
  )
  libop_dep = declare_dependency(
    include_directories: include_directories('subprojects/libop/include', 'compat'),
    link_with: libop_stubs,
  )
endif

conf = configuration_data()

# kTLS support (Linux 4.13+)
if is_linux and opt_ktls.allowed()
  have_ktls = cc.has_header('linux/tls.h')
  if have_ktls
    ktls_aes_gcm_128 = cc.has_header_symbol('linux/tls.h', 'TLS_CIPHER_AES_GCM_128')
    ktls_aes_gcm_256 = cc.has_header_symbol('linux/tls.h', 'TLS_CIPHER_AES_GCM_256')
    ktls_chacha20 = cc.has_header_symbol('linux/tls.h', 'TLS_CIPHER_CHACHA20_POLY1305')
    conf.set('OPSSL_HAVE_KTLS', true)
    conf.set('OPSSL_HAVE_KTLS_AES_GCM_128', ktls_aes_gcm_128)
    conf.set('OPSSL_HAVE_KTLS_AES_GCM_256', ktls_aes_gcm_256)
    conf.set('OPSSL_HAVE_KTLS_CHACHA20', ktls_chacha20)
  elif opt_ktls.enabled()
    error('kTLS requested but linux/tls.h not found')
  endif
endif

# CPU feature detection for crypto acceleration
have_aesni = cc.has_argument('-maes') and cc.has_argument('-mpclmul')
have_avx2 = cc.has_argument('-mavx2')
have_sse4 = cc.has_argument('-msse4.1')
have_sha_ni = cc.has_argument('-msha')
have_arm_neon = cc.has_argument('-mfpu=neon') or host_machine.cpu_family() == 'aarch64'
have_arm_crypto = cc.compiles('''
  #include <arm_neon.h>
  int main(void) { uint8x16_t a = {}; vaeseq_u8(a, a); return 0; }
''', args: ['-march=armv8-a+crypto'], name: 'ARM crypto extensions')

conf.set('OPSSL_HAVE_AESNI', have_aesni)
conf.set('OPSSL_HAVE_AVX2', have_avx2)
conf.set('OPSSL_HAVE_SSE4', have_sse4)
conf.set('OPSSL_HAVE_SHA_NI', have_sha_ni)
conf.set('OPSSL_HAVE_ARM_NEON', have_arm_neon)
conf.set('OPSSL_HAVE_ARM_CRYPTO', have_arm_crypto)

# Post-quantum support
conf.set('OPSSL_HAVE_MLKEM', opt_postquantum.allowed())
conf.set('OPSSL_HAVE_SESSION_EXPORT', opt_session_export.allowed())

# getrandom / getentropy detection
have_getrandom = cc.has_function('getrandom', prefix: '#include <sys/random.h>')
have_getentropy = cc.has_function('getentropy', prefix: '#include <unistd.h>')
have_arc4random = cc.has_function('arc4random_buf')
conf.set('OPSSL_HAVE_GETRANDOM', have_getrandom)
conf.set('OPSSL_HAVE_GETENTROPY', have_getentropy)
conf.set('OPSSL_HAVE_ARC4RANDOM', have_arc4random)

# Constant-time helpers
conf.set('OPSSL_HAVE_EXPLICIT_BZERO', cc.has_function('explicit_bzero', prefix: '#include <string.h>'))
conf.set('OPSSL_HAVE_MEMSET_S', cc.has_function('memset_s', prefix: '#define __STDC_WANT_LIB_EXT1__ 1\n#include <string.h>'))

configure_file(output: 'opssl_config.h', configuration: conf)

# Core library sources (init, error, context)
core_src = files(
  'src/init.c',
  'src/err.c',
  'src/ctx.c',
)

# Crypto sources — hardware-accelerated where available
crypto_src = files(
  'src/crypto/cpuid.c',
  'src/crypto/platform.c',
  'src/crypto/random.c',
  'src/crypto/constant_time.c',
  'src/crypto/cbs.c',
  'src/crypto/sha1.c',
  'src/crypto/sha256.c',
  'src/crypto/sha512.c',
  'src/crypto/sha3.c',
  'src/crypto/hmac.c',
  'src/crypto/hkdf.c',
  'src/crypto/pbkdf2.c',
  'src/crypto/aes.c',
  'src/crypto/aes_gcm.c',
  'src/crypto/chacha20.c',
  'src/crypto/poly1305.c',
  'src/crypto/chacha20_poly1305.c',
  'src/crypto/bignum.c',
  'src/crypto/ecc.c',
  'src/crypto/x25519.c',
  'src/crypto/ed25519.c',
  'src/crypto/rsa.c',
  'src/crypto/dh.c',
)

if opt_postquantum.allowed()
  crypto_src += files('src/crypto/mlkem.c')
endif

if have_aesni
  crypto_src += files('src/crypto/aes_ni.c')
endif

if have_sha_ni
  crypto_src += files('src/crypto/sha256_ni.c')
endif

# TLS protocol sources
tls_src = files(
  'src/tls/record.c',
  'src/tls/handshake.c',
  'src/tls/tls12.c',
  'src/tls/tls13.c',
  'src/tls/extensions.c',
  'src/tls/ciphersuite.c',
  'src/tls/ktls.c',
  'src/tls/keysched.c',
  'src/tls/dtls.c',
)

# X.509 sources
x509_src = files(
  'src/x509/cert.c',
  'src/x509/chain.c',
  'src/x509/pem.c',
  'src/x509/fingerprint.c',
  'src/x509/asn1.c',
  'src/x509/pkey.c',
)

# I/O and session management
io_src = files(
  'src/io/bio.c',
  'src/io/export.c',
)

# Build args
crypto_args = []
if have_aesni
  crypto_args += ['-maes', '-mpclmul', '-mssse3']
endif
if have_avx2
  crypto_args += ['-mavx2']
endif
if have_sha_ni
  crypto_args += ['-msha', '-msse4.1']
endif

# Include dirs
opssl_inc = include_directories('include')

# Main library
libopssl = library('opssl',
  core_src + crypto_src + tls_src + x509_src + io_src,
  include_directories: opssl_inc,
  c_args: crypto_args + ['-D_GNU_SOURCE'],
  dependencies: [threads_dep, math_dep, libop_dep],
  install: true,
)

opssl_dep = declare_dependency(
  include_directories: opssl_inc,
  link_with: libopssl,
)

# CLI tool - minimal version with forward declarations
opssl_cli = executable('opssl',
  'tools/opssl_cli_minimal.c',
  dependencies: [opssl_dep, libop_dep, threads_dep],
  install: true,
)

# Install headers
install_subdir('include/opssl', install_dir: get_option('includedir'))

# pkg-config generation
pkg = import('pkgconfig')
pkg.generate(libopssl,
  name: 'opssl',
  description: 'Minimal TLS 1.2/1.3 library with post-quantum support',
  version: meson.project_version(),
  url: 'https://github.com/ophion/opssl',
  subdirs: ['opssl'],
)

# Tests
if get_option('tests')
  subdir('tests')
endif

# Meson subproject support
meson.override_dependency('opssl', opssl_dep)
