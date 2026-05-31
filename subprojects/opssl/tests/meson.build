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

# ML-KEM shared secret mismatch diagnostic
test_mlkem_debug = executable('test_mlkem_debug',
  'test_mlkem_debug.c',
  dependencies: test_deps,
)
test('mlkem_debug', test_mlkem_debug)

# ML-KEM / ML-DSA NIST ACVP Known-Answer Tests
test_mlkem_kat = executable('test_mlkem_kat',
  'test_mlkem_kat.c',
  dependencies: test_deps,
)
# protocol: 'exitcode' (default) — exit code 77 == SKIP, allowing the test
# to gracefully skip bit-exact comparisons until a deterministic-seed API
# lands without turning the suite red.
test('mlkem_kat', test_mlkem_kat)

# ─── Additional coverage ────────────────────────────────────────────────

test_tls13_handshake = executable('test_tls13_handshake',
  'test_tls13_handshake.c',
  dependencies: test_deps,
)
test('tls13_handshake', test_tls13_handshake, workdir: meson.project_source_root())

test_aead = executable('test_aead',
  'test_aead.c',
  dependencies: test_deps,
)
test('aead', test_aead)

test_x509_chain = executable('test_x509_chain',
  'test_x509_chain.c',
  dependencies: test_deps,
)
test('x509_chain', test_x509_chain, workdir: meson.project_source_root())

test_pq_hybrid = executable('test_pq_hybrid',
  'test_pq_hybrid.c',
  dependencies: test_deps,
)
test('pq_hybrid', test_pq_hybrid)

test_session_resume = executable('test_session_resume',
  'test_session_resume.c',
  dependencies: test_deps,
)
test('session_resume', test_session_resume, workdir: meson.project_source_root())

test_kdf = executable('test_kdf',
  'test_kdf.c',
  dependencies: test_deps,
)
test('kdf', test_kdf)