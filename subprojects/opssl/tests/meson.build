test_deps = [opssl_dep, libop_dep, threads_dep]

# Crypto primitive tests
test_crypto = executable('test_crypto',
  'test_crypto.c',
  dependencies: test_deps,
)
test('crypto', test_crypto)

# TLS handshake tests
test_tls = executable('test_tls',
  'test_tls.c',
  dependencies: test_deps,
)
test('tls', test_tls, workdir: meson.project_source_root())

# X.509 tests
test_x509 = executable('test_x509',
  'test_x509.c',
  dependencies: test_deps,
)
test('x509', test_x509)