# =========================================================================
# libop/include/meson.build — generate libop_config.h and expose include dir
# =========================================================================

# Reuse eggdrop's main cdata (feature-test results) to populate libop_config.h.
configure_file(
  input:         'libop_config.h.meson',
  output:        'libop_config.h',
  configuration: cdata,
)

libop_inc = include_directories('.')
