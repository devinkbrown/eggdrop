# =========================================================================
# libop/include/meson.build — generate config headers and expose include dir
# =========================================================================

# Feature flags populated from eggdrop's cdata.
configure_file(
  input:         'libop_config.h.meson',
  output:        'libop_config.h',
  configuration: cdata,
)

# Platform typedefs and system includes — static header, no substitution.
configure_file(
  input:         'libop-config.h.meson',
  output:        'libop-config.h',
  copy: true,
)

libop_inc = include_directories('.')
